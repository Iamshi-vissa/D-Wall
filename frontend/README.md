# D-WALL frontend

The web app for D-WALL. You upload a QR code or paste a link or UPI string, and it shows the verdict
(Safe, Suspicious or Dangerous), the score and the reasons from the API.

## RUN

Start the backend first (see the [main README](../README.md)), then:

```bash
npm install
npm run dev
```

Open the address Vite prints, usually <http://localhost:5173>. The app calls the API at
<http://localhost:8000>.

## FOLDERS

```
src/        the interface that runs today (React + Vite)
client/     a newer, more complete interface; it doesn't build yet
public/     static files
```

`client/` still depends on packages from the tool it was made with, which aren't in the lockfile.
See Status in the [main README](../README.md#status).
