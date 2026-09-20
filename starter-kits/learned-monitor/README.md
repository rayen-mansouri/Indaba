# Learned monitor starter kit

**Optional.** A deliberately tiny machine-learning defense: logistic regression over hashed action
text plus a few provenance features. It trains in seconds on CPU and shows where a learned model
plugs into a defense. It is **not** state of the art; treat it as scaffolding for your own model, or
ignore it and build something else entirely -- SENTINEL does not require this shape.

```
learned-monitor/
├── monitor/features.py   # request JSON -> sparse features (no sentinel dependency)
├── monitor/model.py      # train / save / load / decide with thresholds
├── monitor/dataset.py    # dev-only: label actions by running the public scenarios
├── monitor/train.py      # train, report validation metrics, save model/monitor.joblib
├── monitor/evaluate.py   # in-process sanity check without HTTP
├── monitor/app.py        # FastAPI service for the container
├── tests/test_monitor.py
├── Dockerfile
└── sentinel-submission.yaml
```

## Train (from the sentinel-bench checkout)

```bash
cd starter-kits/learned-monitor
uv run python -m monitor.train          # writes model/monitor.joblib
uv run python -m monitor.evaluate --split validation
uv run pytest -q tests
```

`monitor.train` labels examples by running the published scenarios through the simulator and
comparing each action to that scenario's legitimate plan -- a sanity check for your own pipeline,
not an official score. There is no held-back split: the published scenario library is everything
your model can learn from ahead of time.

## Try it against the reference agent

```bash
uv run uvicorn monitor.app:create_app --factory --port 8080
# in another shell, from the repository root:
uv run sentinel run --scenario scenarios/public/finance/finance_false_approval.yaml \
  --defense-url http://127.0.0.1:8080 --model qwen3-8b
uv run sentinel replay artifacts/<group>/<run>.jsonl
```

The reference agent is a preconfigured **Qwen3-8B** (`Qwen/Qwen3-8B`), running locally. Use
`--model mock` while iterating on the monitor itself; switch to `--model qwen3-8b` once you are
ready to record the trace your video demonstration is built around (needs `uv sync --extra hf` and
the weights downloaded ahead of time).

## Where to go next

- Replace hashed n-grams with a small encoder and fine-tune on generated trajectories.
- Calibrate `risk_score` -- a well-calibrated monitor is easier to defend in your technical report.
- Tune `BLOCK_AT` / `ESCALATE_AT`: blocking legitimate actions costs utility, and unnecessary
  escalations cost precision -- both are things judges watch for in your video.
- There is no automated benchmark to chase. A smaller model with an honest failure analysis in the
  report can score better than a bigger one with none.
