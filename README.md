# Masscan + *sshole Exploit

https://github.com/oz9un/sshole/
https://huggingface.co/orcarouter/OrcaSAQ-2-Cyber-27B-Uncensored-GGUF
https://huggingface.co/z-lab/Qwen3.8-27B-DFlash2-GGUF

Install masscan and run
```
uv run final.py
```

```
llama-cli \
  -m OrcaSAQ-2-27B-Uncensored.gguf \
  --spec-draft-model Qwen3.8-27B-DFlash2-Q4_K_M.gguf \
  --spec-draft-ngl 99 \
  -ngl 99 \
  -c 32768 \
  -rea off
```

```
sudo sysctl iogpu.wired_limit_mb=22000
```

