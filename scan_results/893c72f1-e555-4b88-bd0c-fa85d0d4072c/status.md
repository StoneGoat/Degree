# Scan Status for https://vuln.stenaeke.org

*Scan ID: `893c72f1-e555-4b88-bd0c-fa85d0d4072c`*
*Scan started: 2025-05-12 16:19:07*

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

### ZAP Scan Completed. AI Analysis Starting.
Started at: 2025-05-12 16:19:13


---

### ZAP AI Analysis Error

```Traceback (most recent call last):
  File "/home/optibot/.local/lib/python3.10/site-packages/urllib3/connection.py", line 198, in _new_conn
    sock = connection.create_connection(
  File "/home/optibot/.local/lib/python3.10/site-packages/urllib3/util/connection.py", line 85, in create_connection
    raise err
  File "/home/optibot/.local/lib/python3.10/site-packages/urllib3/util/connection.py", line 73, in create_connection
    sock.connect(sa)
ConnectionRefusedError: [Errno 111] Connection refused

The above exception was the direct cause of the following exception:

Traceback (most recent call last):
  File "/home/optibot/.local/lib/python3.10/site-packages/urllib3/connectionpool.py", line 787, in urlopen
    response = self._make_request(
  File "/home/optibot/.local/lib/python3.10/site-packages/urllib3/connectionpool.py", line 493, in _make_request
    conn.request(
  File "/home/optibot/.local/lib/python3.10/site-packages/urllib3/connection.py", line 445, in request
    self.endheaders()
  File "/usr/lib/python3.10/http/client.py", line 1278, in endheaders
    self._send_output(message_body, encode_chunked=encode_chunked)
  File "/usr/lib/python3.10/http/client.py", line 1038, in _send_output
    self.send(msg)
  File "/usr/lib/python3.10/http/client.py", line 976, in send
    self.connect()
  File "/home/optibot/.local/lib/python3.10/site-packages/urllib3/connection.py", line 276, in connect
    self.sock = self._new_conn()
  File "/home/optibot/.local/lib/python3.10/site-packages/urllib3/connection.py", line 213, in _new_conn
    raise NewConnectionError(
urllib3.exceptions.NewConnectionError: <urllib3.connection.HTTPConnection object at 0x7f6bb0574a00>: Failed to establish a new connection: [Errno 111] Connection refused

The above exception was the direct cause of the following exception:

Traceback (most recent call last):
  File "/home/optibot/.local/lib/python3.10/site-packages/requests/adapters.py", line 667, in send
    resp = conn.urlopen(
  File "/home/optibot/.local/lib/python3.10/site-packages/urllib3/connectionpool.py", line 841, in urlopen
    retries = retries.increment(
  File "/home/optibot/.local/lib/python3.10/site-packages/urllib3/util/retry.py", line 519, in increment
    raise MaxRetryError(_pool, url, reason) from reason  # type: ignore[arg-type]
urllib3.exceptions.MaxRetryError: HTTPConnectionPool(host='127.0.0.1', port=9000): Max retries exceeded with url: /chat (Caused by NewConnectionError('<urllib3.connection.HTTPConnection object at 0x7f6bb0574a00>: Failed to establish a new connection: [Errno 111] Connection refused'))

During handling of the above exception, another exception occurred:

Traceback (most recent call last):
  File "/home/optibot/Degree/frontend.py", line 215, in send_zap_to_AI
    chat.run_zap_analysis(f"scan_results/{scan_id}/zap.xml", scan_id, level)
  File "/home/optibot/Degree/AI/chat.py", line 587, in run_zap_analysis
    test_alert_items(xml_file_path, model_id="WhiteRabbitNeo/Llama-3-WhiteRabbitNeo-8B-v2.0", scan_id=scan_id, level=level)
  File "/home/optibot/Degree/AI/chat.py", line 177, in test_alert_items
    chat_id, _ = send_chat_request(prompt, role="system", model_id=model_id)
  File "/home/optibot/Degree/AI/chat.py", line 30, in send_chat_request
    response = requests.post(API_URL, json=payload)
  File "/home/optibot/.local/lib/python3.10/site-packages/requests/api.py", line 115, in post
    return request("post", url, data=data, json=json, **kwargs)
  File "/home/optibot/.local/lib/python3.10/site-packages/requests/api.py", line 59, in request
    return session.request(method=method, url=url, **kwargs)
  File "/home/optibot/.local/lib/python3.10/site-packages/requests/sessions.py", line 589, in request
    resp = self.send(prep, **send_kwargs)
  File "/home/optibot/.local/lib/python3.10/site-packages/requests/sessions.py", line 703, in send
    r = adapter.send(request, **kwargs)
  File "/home/optibot/.local/lib/python3.10/site-packages/requests/adapters.py", line 700, in send
    raise ConnectionError(e, request=request)
requests.exceptions.ConnectionError: HTTPConnectionPool(host='127.0.0.1', port=9000): Max retries exceeded with url: /chat (Caused by NewConnectionError('<urllib3.connection.HTTPConnection object at 0x7f6bb0574a00>: Failed to establish a new connection: [Errno 111] Connection refused'))
```

---

### Overview AI Analysis Error

```Traceback (most recent call last):
  File "/home/optibot/.local/lib/python3.10/site-packages/urllib3/connection.py", line 198, in _new_conn
    sock = connection.create_connection(
  File "/home/optibot/.local/lib/python3.10/site-packages/urllib3/util/connection.py", line 85, in create_connection
    raise err
  File "/home/optibot/.local/lib/python3.10/site-packages/urllib3/util/connection.py", line 73, in create_connection
    sock.connect(sa)
ConnectionRefusedError: [Errno 111] Connection refused

The above exception was the direct cause of the following exception:

Traceback (most recent call last):
  File "/home/optibot/.local/lib/python3.10/site-packages/urllib3/connectionpool.py", line 787, in urlopen
    response = self._make_request(
  File "/home/optibot/.local/lib/python3.10/site-packages/urllib3/connectionpool.py", line 493, in _make_request
    conn.request(
  File "/home/optibot/.local/lib/python3.10/site-packages/urllib3/connection.py", line 445, in request
    self.endheaders()
  File "/usr/lib/python3.10/http/client.py", line 1278, in endheaders
    self._send_output(message_body, encode_chunked=encode_chunked)
  File "/usr/lib/python3.10/http/client.py", line 1038, in _send_output
    self.send(msg)
  File "/usr/lib/python3.10/http/client.py", line 976, in send
    self.connect()
  File "/home/optibot/.local/lib/python3.10/site-packages/urllib3/connection.py", line 276, in connect
    self.sock = self._new_conn()
  File "/home/optibot/.local/lib/python3.10/site-packages/urllib3/connection.py", line 213, in _new_conn
    raise NewConnectionError(
urllib3.exceptions.NewConnectionError: <urllib3.connection.HTTPConnection object at 0x7f6bb0574190>: Failed to establish a new connection: [Errno 111] Connection refused

The above exception was the direct cause of the following exception:

Traceback (most recent call last):
  File "/home/optibot/.local/lib/python3.10/site-packages/requests/adapters.py", line 667, in send
    resp = conn.urlopen(
  File "/home/optibot/.local/lib/python3.10/site-packages/urllib3/connectionpool.py", line 841, in urlopen
    retries = retries.increment(
  File "/home/optibot/.local/lib/python3.10/site-packages/urllib3/util/retry.py", line 519, in increment
    raise MaxRetryError(_pool, url, reason) from reason  # type: ignore[arg-type]
urllib3.exceptions.MaxRetryError: HTTPConnectionPool(host='127.0.0.1', port=9000): Max retries exceeded with url: /chat (Caused by NewConnectionError('<urllib3.connection.HTTPConnection object at 0x7f6bb0574190>: Failed to establish a new connection: [Errno 111] Connection refused'))

During handling of the above exception, another exception occurred:

Traceback (most recent call last):
  File "/home/optibot/Degree/frontend.py", line 268, in send_overview_to_AI
    chat.run_overview_analysis(xml_file_path=xml_file_path, scan_id=scan_id, level=level)
  File "/home/optibot/Degree/AI/chat.py", line 596, in run_overview_analysis
    test_scan_overview(xml_file_path=xml_file_path, scan_id=scan_id, level=level)
  File "/home/optibot/Degree/AI/chat.py", line 736, in test_scan_overview
    chat_id, _ = send_chat_request(system_prompt, role="system", model_id=model_id)
  File "/home/optibot/Degree/AI/chat.py", line 30, in send_chat_request
    response = requests.post(API_URL, json=payload)
  File "/home/optibot/.local/lib/python3.10/site-packages/requests/api.py", line 115, in post
    return request("post", url, data=data, json=json, **kwargs)
  File "/home/optibot/.local/lib/python3.10/site-packages/requests/api.py", line 59, in request
    return session.request(method=method, url=url, **kwargs)
  File "/home/optibot/.local/lib/python3.10/site-packages/requests/sessions.py", line 589, in request
    resp = self.send(prep, **send_kwargs)
  File "/home/optibot/.local/lib/python3.10/site-packages/requests/sessions.py", line 703, in send
    r = adapter.send(request, **kwargs)
  File "/home/optibot/.local/lib/python3.10/site-packages/requests/adapters.py", line 700, in send
    raise ConnectionError(e, request=request)
requests.exceptions.ConnectionError: HTTPConnectionPool(host='127.0.0.1', port=9000): Max retries exceeded with url: /chat (Caused by NewConnectionError('<urllib3.connection.HTTPConnection object at 0x7f6bb0574190>: Failed to establish a new connection: [Errno 111] Connection refused'))
```

---

## Generating Visual Summaries...

---

### Graph Generation Status Updates

Graph Generation Status: Graphs generated successfully into directory: `scan_results/893c72f1-e555-4b88-bd0c-fa85d0d4072c`.

Missing Graphs: Expected graph files not found: `1_zap_risk_distribution.png`, `2_zap_alert_counts.png`, `4_nmap_port_status.png`

Markdown Write Error: Failed to write graph links to vulnerability.md: `[Errno 2] No such file or directory: '/home/optibot/Degree/scan_results/893c72f1-e555-4b88-bd0c-fa85d0d4072c/report.json'`

---

## Scan Process Complete

Finished at: 2025-05-12 16:19:13
Total duration: 0:00:06

