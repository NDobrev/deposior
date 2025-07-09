# deposior

## Running the web interface

1. Install the dependencies:

```bash
pip install -r requirements.txt
```

2. Start the server:

```bash
uvicorn main:app --reload
```

3. Open your browser at [http://localhost:8000](http://localhost:8000) to use the interface.

Once running, the interface lists saved wallets. Click **Deposit** next to a wallet to automatically
generate validator keys, create a keystore and deposit file, and submit the deposit transaction.

The web pages now leverage the Bootstrap CSS framework to provide a responsive layout with a dark sci-fi look.
Buttons glow with a neon animation powered by Animate.css.
