import uvicorn

if __name__ == "__main__":
    print("Booting Data Privacy Toolkit Backend...")
    # This points to the app instance inside backend/app.py
    uvicorn.run("backend.app:app", host="0.0.0.0", port=8000, reload=True)