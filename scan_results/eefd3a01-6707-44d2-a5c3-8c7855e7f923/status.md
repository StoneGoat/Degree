# Scan Status for flamman.se

*Scan ID: `eefd3a01-6707-44d2-a5c3-8c7855e7f923`*
*Scan started: 2025-05-15 13:08:24*

## Initializing Scan

Please wait while we analyze the target. This page will update automatically.

---

## Scanning in Progress...

Nmap and Nikto scans will start immediately and their AI analyses will fire as each XML completes.

---

### ZAP Scan Completed. AI Analysis Starting.
Started at: 2025-05-15 13:08:38


---

### ZAP AI Analysis Completed.
Finished at: 2025-05-15 13:10:29


---

### Nikto Scan Completed. AI Analysis Starting.
Started at: 2025-05-15 13:11:05


---

### Nmap Scan Completed. AI Analysis Starting.
Started at: 2025-05-15 13:11:31


---

### Nikto AI Analysis Completed.
Finished at: 2025-05-15 13:12:10


---

### Nmap AI Analysis Completed.
Finished at: 2025-05-15 13:23:20


---

## Scan Tool Execution Complete

Nmap and Nikto have finished (and triggered AI). Starting ZAP now.

---

### Overview AI Analysis Error

```Traceback (most recent call last):
  File "/home/optibot/.local/lib/python3.10/site-packages/urllib3/connectionpool.py", line 787, in urlopen
    response = self._make_request(
  File "/home/optibot/.local/lib/python3.10/site-packages/urllib3/connectionpool.py", line 534, in _make_request
    response = conn.getresponse()
  File "/home/optibot/.local/lib/python3.10/site-packages/urllib3/connection.py", line 516, in getresponse
    httplib_response = super().getresponse()
  File "/usr/lib/python3.10/http/client.py", line 1375, in getresponse
    response.begin()
  File "/usr/lib/python3.10/http/client.py", line 318, in begin
    version, status, reason = self._read_status()
  File "/usr/lib/python3.10/http/client.py", line 279, in _read_status
    line = str(self.fp.readline(_MAXLINE + 1), "iso-8859-1")
  File "/usr/lib/python3.10/socket.py", line 705, in readinto
    return self._sock.recv_into(b)
ConnectionResetError: [Errno 104] Connection reset by peer

During handling of the above exception, another exception occurred:

Traceback (most recent call last):
  File "/home/optibot/.local/lib/python3.10/site-packages/requests/adapters.py", line 667, in send
    resp = conn.urlopen(
  File "/home/optibot/.local/lib/python3.10/site-packages/urllib3/connectionpool.py", line 841, in urlopen
    retries = retries.increment(
  File "/home/optibot/.local/lib/python3.10/site-packages/urllib3/util/retry.py", line 474, in increment
    raise reraise(type(error), error, _stacktrace)
  File "/home/optibot/.local/lib/python3.10/site-packages/urllib3/util/util.py", line 38, in reraise
    raise value.with_traceback(tb)
  File "/home/optibot/.local/lib/python3.10/site-packages/urllib3/connectionpool.py", line 787, in urlopen
    response = self._make_request(
  File "/home/optibot/.local/lib/python3.10/site-packages/urllib3/connectionpool.py", line 534, in _make_request
    response = conn.getresponse()
  File "/home/optibot/.local/lib/python3.10/site-packages/urllib3/connection.py", line 516, in getresponse
    httplib_response = super().getresponse()
  File "/usr/lib/python3.10/http/client.py", line 1375, in getresponse
    response.begin()
  File "/usr/lib/python3.10/http/client.py", line 318, in begin
    version, status, reason = self._read_status()
  File "/usr/lib/python3.10/http/client.py", line 279, in _read_status
    line = str(self.fp.readline(_MAXLINE + 1), "iso-8859-1")
  File "/usr/lib/python3.10/socket.py", line 705, in readinto
    return self._sock.recv_into(b)
urllib3.exceptions.ProtocolError: ('Connection aborted.', ConnectionResetError(104, 'Connection reset by peer'))

During handling of the above exception, another exception occurred:

Traceback (most recent call last):
  File "/home/optibot/Degree/frontend.py", line 276, in send_overview_to_AI
    chat.run_overview_analysis(xml_file_path=xml_file_path, scan_id=scan_id, level=level)
  File "/home/optibot/Degree/AI/chat.py", line 908, in run_overview_analysis
    test_nmap_object(xml_file_path, model_id="WhiteRabbitNeo/Llama-3-WhiteRabbitNeo-8B-v2.0", scan_id=scan_id, level=level)
  File "/home/optibot/Degree/AI/chat.py", line 1057, in test_scan_overview
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
  File "/home/optibot/.local/lib/python3.10/site-packages/requests/adapters.py", line 682, in send
    raise ConnectionError(err, request=request)
requests.exceptions.ConnectionError: ('Connection aborted.', ConnectionResetError(104, 'Connection reset by peer'))
```

---

## Generating Visual Summaries...

---

### Graph Generation Status Updates

Graph Generation Status: Graphs generated successfully into directory: `scan_results/eefd3a01-6707-44d2-a5c3-8c7855e7f923`.

---

## Scan Process Complete

Finished at: 2025-05-15 13:23:22
Total duration: 0:14:57

