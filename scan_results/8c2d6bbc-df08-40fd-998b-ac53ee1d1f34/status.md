# Scan Status for flamman.se

*Scan ID: `8c2d6bbc-df08-40fd-998b-ac53ee1d1f34`*
*Scan started: 2025-05-07 14:29:50*

## Initializing Scan

Please wait while we analyze the target. This page will update automatically.

---

## Scanning in Progress...

Nmap and Nikto scans will start immediately and their AI analyses will fire as each XML completes.

---

## Scan Tool Execution Complete

Nmap and Nikto have finished (and triggered AI). Starting ZAP now.

---

## ZAP AI Analysis Starting

---

### ZAP AI Analysis Error

```Traceback (most recent call last):
  File "/home/optibot/Degree/frontend.py", line 198, in send_zap_to_AI
    chat.run_zap_analysis(f"scan_results/{scan_id}/zap.xml", scan_id, level)
  File "/home/optibot/Degree/AI/chat.py", line 579, in run_zap_analysis
    test_alert_items(xml_file_path, model_id="WhiteRabbitNeo/Llama-3-WhiteRabbitNeo-8B-v2.0", scan_id=scan_id, level=level)
  File "/home/optibot/Degree/AI/chat.py", line 193, in test_alert_items
    sections = parse_markdown_response_ordered(response)
  File "/home/optibot/Degree/AI/chat.py", line 99, in parse_markdown_response_ordered
    headers = list(header_pattern.finditer(response))
TypeError: expected string or bytes-like object
```

---

## Generating Visual Summaries...

---

### Graph Generation Status Updates

Graph Generation Status: Graph generation failed or was skipped (returned None). No graphs added.

---

## Scan Process Complete

Finished at: 2025-05-07 14:41:32
Total duration: 0:11:42

