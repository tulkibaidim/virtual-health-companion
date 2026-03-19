# Virtual Health Companion

## Deploy Instructions

### Frontend (Vercel)
Upload `index.html` to a GitHub repo, connect to Vercel.

### Backend (Railway)
1. Push this repo to GitHub
2. Go to railway.app → New Project → Deploy from GitHub
3. Set environment variables:
   - `VHC_SECRET` = any random long string
   - `GROQ_API_KEY` = your Groq API key
   - `FIREBASE_KEY_PATH` = path to your serviceAccountKey.json (optional)
4. Railway will auto-detect Python and deploy

### Environment Variables
| Variable | Description |
|---|---|
| `VHC_SECRET` | JWT secret key |
| `GROQ_API_KEY` | Groq AI API key for chat |
| `FIREBASE_KEY_PATH` | Path to Firebase service account (optional) |
