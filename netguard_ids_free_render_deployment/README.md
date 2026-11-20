# NetGuard IDS — Free hosted demonstration

This repository is a deployment copy of the NetGuard IDS student prototype.

## Important demonstration limitation

The hosted free web service displays seeded sample alerts and packet-log records.
It does **not** capture live packets from a university network or from the visitor's
computer. Scapy packet capture remains available in the local installation where
the application has access to an authorized network interface.

All seeded addresses use documentation-only IP ranges (RFC 5737).

## Deploy on Render (Free)

1. Push the contents of this folder to a GitHub repository.
2. In Render, choose **New + → Blueprint** and connect that repository.
3. Render reads `render.yaml` and creates the `netguard-ids-demo` free web service.
4. Wait for the build and deployment to complete.
5. Open the `onrender.com` URL shown in the Render dashboard.

The free service may sleep after inactivity and the first request after sleep can be
slow. Its filesystem is ephemeral, so sample records are automatically recreated
when the database is empty.

## Routes

- `/` — Dashboard
- `/alerts` — Security alerts
- `/logs` — Network packet logs

## Local development

Install dependencies and run `python app.py`. The local sniffer is enabled by
default. Only capture traffic on networks for which you have permission.
