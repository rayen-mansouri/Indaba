"""SENTINEL participant command-line interface."""

from __future__ import annotations

import json
import runpy
from collections.abc import Callable
from pathlib import Path
from typing import Annotated, Any

import typer
from rich.console import Console
from rich.table import Table

from sentinel.config import CompetitionConfig, find_root, load_competition
from sentinel.core.scenario import (
    ScenarioError,
    discover_scenarios,
    load_scenario,
    scenario_json_schema,
)
from sentinel.defenses.interface import Defense

app = typer.Typer(
    help="SENTINEL: build and demonstrate safety for autonomous AI agents.",
    no_args_is_help=True,
    pretty_exceptions_show_locals=False,
)
scenarios_app = typer.Typer(help="Validate, list, and export scenario schemas.", no_args_is_help=True)
eval_app = typer.Typer(help="Evaluate a defense on a scenario split.", no_args_is_help=True)
submission_app = typer.Typer(help="Validate participant submissions.", no_args_is_help=True)
fixtures_app = typer.Typer(help="Synthetic fixture data.", no_args_is_help=True)
serve_app = typer.Typer(help="Run a local defense helper service.", no_args_is_help=True)
app.add_typer(scenarios_app, name="scenarios")
app.add_typer(eval_app, name="eval")
app.add_typer(submission_app, name="submission")
app.add_typer(fixtures_app, name="fixtures")
app.add_typer(serve_app, name="serve")

console = Console()
JsonFlag = Annotated[bool, typer.Option("--json", help="Machine-readable JSON output.")]
ConfigOpt = Annotated[Path | None, typer.Option("--config", help="competition.yaml to use.")]
ArtifactsOpt = Annotated[Path, typer.Option("--artifacts", help="Artifact output directory.")]


def _emit_json(data: Any) -> None:
    typer.echo(json.dumps(data, indent=2, sort_keys=True, default=str))


def _root() -> Path:
    return find_root()


def _competition(config: Path | None) -> CompetitionConfig:
    return load_competition(config, _root())


def _defense_factory(
    defense: str | None, defense_url: str | None, competition: CompetitionConfig
) -> Callable[[], Defense]:
    if bool(defense) == bool(defense_url):
        raise typer.BadParameter("pass exactly one of --defense or --defense-url")
    if defense_url:
        from sentinel.defenses.client import HttpDefense

        runtime = competition.defense

        def http_factory() -> Defense:
            return HttpDefense(
                defense_url,
                timeout_s=runtime.timeout_s,
                transport_retries=runtime.transport_retries,
                fail_mode=runtime.fail_mode,
                name="http_defense",
            )

        return http_factory
    from sentinel.defenses.baselines import BASELINES

    key = (defense or "").replace("-", "_")
    if key not in BASELINES:
        raise typer.BadParameter(f"unknown defense {defense!r}; choose from {', '.join(sorted(BASELINES))}")
    return BASELINES[key]


def _attacker_factory(attacker: str) -> Callable[[], Any] | None:
    if attacker == "none":
        return None
    from sentinel.attackers.baselines import ATTACKERS

    if attacker not in ATTACKERS:
        raise typer.BadParameter(f"unknown attacker {attacker!r}; choose from none, {', '.join(ATTACKERS)}")
    return ATTACKERS[attacker]


def _model_factory(model: str) -> Callable[[], Any]:
    """mock | qwen3-8b/Hugging Face path | lmstudio[:loaded-model-id]."""
    if model == "mock":
        from sentinel.models.mock import MockModelAdapter

        return MockModelAdapter
    if model == "lmstudio" or model.startswith("lmstudio:"):
        from sentinel.models.lmstudio_adapter import DEFAULT_LMSTUDIO_MODEL, LMStudioModelAdapter

        identifier = model.partition(":")[2] or DEFAULT_LMSTUDIO_MODEL
        return lambda: LMStudioModelAdapter(identifier)
    from sentinel.models.hf_adapter import DEFAULT_MODEL, HFModelAdapter

    path = DEFAULT_MODEL if model in ("qwen3-8b", "qwen3", "qwen", "default") else model
    cache: list[Any] = []  # load the 8B weights once per process, not once per scenario

    def factory() -> Any:
        if not cache:
            cache.append(HFModelAdapter(path))
        return cache[0]

    return factory


# ---- scenarios ---------------------------------------------------------------------------------


@scenarios_app.command("validate")
def scenarios_validate(path: Path, as_json: JsonFlag = False) -> None:
    """Validate scenario files (schema + fixtures + policies + domain tools)."""
    from sentinel.evaluator.scenario_checks import check_path

    files = discover_scenarios(path)
    if not files:
        raise typer.BadParameter(f"no scenario files found under {path}")
    root = _root()
    reports = [check_path(file, root) for file in files]
    ids = [r.scenario_id for r in reports if r.scenario_id]
    duplicates = sorted({i for i in ids if ids.count(i) > 1})
    for report in reports:
        if report.scenario_id in duplicates:
            report.problems.append(f"duplicate scenario id {report.scenario_id!r}")
    failed = [r for r in reports if not r.ok]
    if as_json:
        _emit_json(
            {
                "checked": len(reports),
                "failed": len(failed),
                "results": [{"path": r.path, "id": r.scenario_id, "problems": r.problems} for r in reports],
            }
        )
    else:
        for report in reports:
            status = "[green]ok[/green]" if report.ok else "[red]FAIL[/red]"
            console.print(f"{status} {report.path}")
            for problem in report.problems:
                console.print(f"     - {problem}")
        console.print(f"{len(reports) - len(failed)}/{len(reports)} scenarios valid")
    if failed:
        raise typer.Exit(1)


@scenarios_app.command("list")
def scenarios_list(path: Path, as_json: JsonFlag = False) -> None:
    """List scenarios with domain, attack family, and tags."""
    rows: list[dict[str, Any]] = []
    for file in discover_scenarios(path):
        try:
            s = load_scenario(file)
        except ScenarioError as exc:
            rows.append({"id": None, "path": str(file), "error": exc.problems})
            continue
        rows.append(
            {
                "id": s.id,
                "path": str(file),
                "domain": s.domain.value,
                "split": s.split.value,
                "attack_family": s.attack.family.value,
                "difficulty": s.attack.difficulty,
                "tags": s.tags,
                "title": s.title,
            }
        )
    if as_json:
        _emit_json(rows)
        return
    table = Table("id", "domain", "split", "attack", "tags", "title")
    for row in rows:
        if row.get("id") is None:
            table.add_row("[red]invalid[/red]", "", "", "", "", row["path"])
        else:
            table.add_row(
                row["id"], row["domain"], row["split"], row["attack_family"], ",".join(row["tags"]), row["title"]
            )
    console.print(table)


@scenarios_app.command("schema")
def scenarios_schema(out: Annotated[Path | None, typer.Option("--out")] = None) -> None:
    """Export the scenario JSON Schema for authoring tools and editors."""
    schema = json.dumps(scenario_json_schema(), indent=2, sort_keys=True) + "\n"
    if out:
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(schema)
        console.print(f"wrote {out}")
    else:
        typer.echo(schema)


# ---- run / eval --------------------------------------------------------------------------------


def _print_outcome(outcome: Any) -> None:
    console.print(
        f"[bold]{outcome.scenario_id}[/bold] defense={outcome.defense} steps={outcome.steps} "
        f"termination={outcome.termination}"
    )
    console.print(
        f"  task_success={outcome.task_success} attack_success={outcome.attack_success} "
        f"critical_violation={outcome.critical_violation} data_flow_violation={outcome.data_flow_violation}"
    )
    for grader in outcome.grader_results:
        mark = "[green]pass[/green]" if grader.passed else "[red]fail[/red]"
        console.print(f"  {mark} {grader.condition} {grader.detail}")
    for finding in outcome.findings:
        console.print(f"  [yellow]{finding['severity']}[/yellow] {finding['rule_id']}: {finding['message']}")


@app.command("run")
def run(
    scenario: Annotated[Path, typer.Option("--scenario", help="Scenario YAML file.")],
    defense: Annotated[str | None, typer.Option("--defense", help="Baseline defense name.")] = None,
    defense_url: Annotated[str | None, typer.Option("--defense-url", help="Defense service URL.")] = None,
    attacker: Annotated[str, typer.Option(help="none | static | mutation")] = "static",
    attack_mode: Annotated[str, typer.Option(help="static | adaptive | none")] = "static",
    model: Annotated[str, typer.Option(help="mock | qwen3-8b | local HF path | lmstudio[:loaded-model-id]")] = "mock",
    artifacts: ArtifactsOpt = Path("artifacts"),
    timeline: Annotated[bool, typer.Option("--timeline/--no-timeline")] = True,
    config: ConfigOpt = None,
    as_json: JsonFlag = False,
) -> None:
    """Run one scenario and write its JSONL event artifact."""
    from sentinel.evaluator.replay import render_timeline
    from sentinel.evaluator.runner import AttackMode, RunConfig, eval_group_name, run_scenario
    from sentinel.storage.runs import ArtifactStore

    competition = _competition(config)
    loaded = load_scenario(scenario)
    factory = _defense_factory(defense, defense_url, competition)
    attacker_factory = _attacker_factory(attacker)
    if attacker_factory is None:
        attack_mode = "none"
    instance = factory()
    store = ArtifactStore(artifacts)
    group = store.unique_group(eval_group_name(f"run-{loaded.id}", instance.name))
    run_config = RunConfig(
        root=_root(),
        competition=competition,
        attack_mode=AttackMode(attack_mode),
        model_factory=_model_factory(model),
        include_reference_plan=(model == "mock"),
        artifacts=store,
        artifact_group=group,
    )
    try:
        result = run_scenario(loaded, instance, run_config, attacker_factory() if attacker_factory else None)
    finally:
        instance.close()
    if as_json:
        _emit_json({"artifact": str(result.artifact), "outcome": result.outcome.model_dump(mode="json")})
        return
    if timeline:
        for line in render_timeline(list(result.log.events)):
            console.print(line, markup=False, highlight=False)
    _print_outcome(result.outcome)
    console.print(f"artifact: {result.artifact}")


def _scorecard_table(report: Any) -> Table:
    m, s = report.metrics, report.score

    def fmt(value: float | None) -> str:
        return "n/a" if value is None else f"{value:.3f}"

    table = Table(title=f"SENTINEL scorecard: {report.split} / {report.defense}", show_header=True)
    table.add_column("metric")
    table.add_column("value", justify="right")
    rows = [
        ("scenarios", str(m.scenario_count)),
        ("benign / attack", f"{m.benign_count} / {m.attack_count}"),
        ("BTU (higher better)", fmt(m.btu)),
        ("ASR (lower better)", fmt(m.asr)),
        ("CVR (lower better)", fmt(m.cvr)),
        ("FBR (lower better)", fmt(m.fbr)),
        ("UER unnecessary escalations", fmt(m.uer)),
        ("TUI", fmt(m.tui)),
        ("DFI", fmt(m.dfi)),
        ("escalation rate", fmt(m.escalation_rate)),
        ("escalation precision", fmt(m.escalation_precision)),
        ("Brier", fmt(m.brier)),
        ("ECE", fmt(m.ece)),
        ("latency median ms", fmt(m.latency_median_ms)),
        ("latency p95 ms", fmt(m.latency_p95_ms)),
        ("defense errors", str(m.defense_errors)),
        ("core score", fmt(s.core)),
        ("official score", fmt(s.official_score)),
        ("eligible (utility gate)", str(s.eligible)),
        ("score config final", str(s.config_final)),
    ]
    for name, value in rows:
        table.add_row(name, value)
    return table


def _run_eval(
    split: str,
    scenarios_path: Path,
    defense: str | None,
    defense_url: str | None,
    attacker: str,
    attack_mode: str,
    model: str,
    artifacts: Path,
    config: Path | None,
    as_json: bool,
    output: Path | None,
) -> None:
    from sentinel.evaluator.runner import (
        AttackMode,
        RunConfig,
        eval_group_name,
        evaluate,
        load_suite,
    )
    from sentinel.storage.runs import ArtifactStore

    competition = _competition(config)
    try:
        suite = load_suite(scenarios_path)
    except ScenarioError as exc:
        raise typer.BadParameter(f"no scenarios found under {scenarios_path}") from exc
    wrong = [s.id for s in suite if s.split.value != split]
    if wrong:
        raise typer.BadParameter(f"scenarios with a split other than {split!r}: {', '.join(wrong[:5])}")
    factory = _defense_factory(defense, defense_url, competition)
    name = defense or "http_defense"
    store = ArtifactStore(artifacts)
    group = store.unique_group(eval_group_name(split, name))
    run_config = RunConfig(
        root=_root(),
        competition=competition,
        attack_mode=AttackMode(attack_mode),
        model_factory=_model_factory(model),
        include_reference_plan=(model == "mock"),
        artifacts=store,
        artifact_group=group,
    )
    attacker_factory = _attacker_factory(attacker)
    if attacker_factory is None:
        run_config.attack_mode = AttackMode.NONE
    report = evaluate(suite, factory, run_config, attacker_factory)
    view = report.participant_view()
    scorecard_path = store.write_json("scorecards", group, view)
    if output:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(view, indent=2, sort_keys=True) + "\n")
    if as_json:
        _emit_json(view)
        return
    console.print(_scorecard_table(report))
    if not report.score.eligible:
        console.print(f"[yellow]{report.score.gate_reason}[/yellow]")
    if not report.score.config_final:
        console.print("[dim]This composite score is a local diagnostic, not the jury score.[/dim]")
    console.print(f"deterministic digest: {report.deterministic_digest}")
    console.print(f"scorecard: {scorecard_path}")


def _eval_command(split: str, default_path: Callable[[], Path]) -> Callable[..., None]:
    def command(
        defense: Annotated[str | None, typer.Option("--defense", help="Baseline defense name.")] = None,
        defense_url: Annotated[str | None, typer.Option("--defense-url", help="Defense service URL.")] = None,
        scenarios: Annotated[Path | None, typer.Option("--scenarios", help="Override scenario path.")] = None,
        attacker: Annotated[str, typer.Option(help="none | static | mutation")] = "static",
        attack_mode: Annotated[str, typer.Option(help="static | adaptive | none")] = "static",
        model: Annotated[
            str, typer.Option(help="mock | qwen3-8b | local HF path | lmstudio[:loaded-model-id]")
        ] = "mock",
        artifacts: ArtifactsOpt = Path("artifacts"),
        config: ConfigOpt = None,
        output: Annotated[Path | None, typer.Option("--output", help="Also write the scorecard here.")] = None,
        as_json: JsonFlag = False,
    ) -> None:
        _run_eval(
            split,
            scenarios or default_path(),
            defense,
            defense_url,
            attacker,
            attack_mode,
            model,
            artifacts,
            config,
            as_json,
            output,
        )

    command.__doc__ = f"Run optional local diagnostics on the {split} scenarios."
    return command


eval_app.command("public")(_eval_command("public", lambda: _root() / "scenarios" / "public"))
eval_app.command("validation")(_eval_command("validation", lambda: _root() / "scenarios" / "validation"))


# ---- replay / fixtures -------------------------------------------------------------------------


@app.command("replay")
def replay(artifact: Path, as_json: JsonFlag = False) -> None:
    """Print a human-readable timeline for a JSONL run artifact."""
    from sentinel.evaluator.replay import render_timeline
    from sentinel.storage.runs import read_events

    events = read_events(artifact)
    if as_json:
        _emit_json([e.model_dump(mode="json") for e in events])
        return
    for line in render_timeline(events):
        console.print(line, markup=False, highlight=False)


@fixtures_app.command("generate")
def fixtures_generate(
    scenarios: Annotated[
        bool, typer.Option("--scenarios/--no-scenarios", help="Also regenerate public/validation scenarios.")
    ] = False,
) -> None:
    """Regenerate deterministic synthetic fixtures (and optionally public scenarios)."""
    root = _root()
    for script in ["generate_fixture_data.py", *(["generate_public_scenarios.py"] if scenarios else [])]:
        path = root / "scripts" / script
        if not path.is_file():
            raise typer.BadParameter(f"{path} not found; run from a sentinel-bench checkout")
        runpy.run_path(str(path), run_name="__main__")


# ---- submissions -------------------------------------------------------------------------------


@submission_app.command("validate")
def submission_validate(
    target: Annotated[str, typer.Argument(help="Submission directory or Docker image reference.")],
    live_url: Annotated[str | None, typer.Option("--live-url", help="Also contract-test a running service.")] = None,
    as_json: JsonFlag = False,
) -> None:
    """Optional static checks for a defense directory or image."""
    from sentinel.sandbox.submission import validate_submission

    report = validate_submission(target, live_url=live_url)
    if as_json:
        _emit_json(report.to_dict())
    else:
        for check in report.checks:
            mark = {"pass": "[green]pass[/green]", "warn": "[yellow]warn[/yellow]", "fail": "[red]fail[/red]"}[
                check.status
            ]
            console.print(f"{mark} {check.name}: {check.detail}")
        console.print("[green]submission valid[/green]" if report.ok else "[red]submission invalid[/red]")
    if not report.ok:
        raise typer.Exit(1)


# ---- services ----------------------------------------------------------------------------------


@serve_app.command("defense")
def serve_defense(
    baseline: Annotated[str, typer.Option(help="Baseline defense to expose.")] = "provenance",
    host: str = "127.0.0.1",
    port: int = 8080,
) -> None:
    """Serve a baseline defense over the official HTTP API."""
    import uvicorn

    from sentinel.api.defense_app import create_defense_app
    from sentinel.defenses.baselines import get_baseline

    uvicorn.run(create_defense_app(get_baseline(baseline)), host=host, port=port)


if __name__ == "__main__":  # pragma: no cover
    app()
