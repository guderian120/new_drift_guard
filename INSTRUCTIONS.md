# DriftGuard (Django Edition) Setup Instructions

Since the automated setup script encountered environment restrictions, please follow these manual steps to get the project running.

## 1. Prerequisites
Ensure you have Python installed and are in the `driftguard_django` directory.

## 2. Install Dependencies
Run the following command to install Django and other required packages:
```bash
pip install -r requirements.txt
```

## 3. Initialize Database
Run the migrations to create the SQLite database:
```bash
python manage.py migrate
```

## 4. Create Admin User
Create a user to log in to the system:
```bash
python manage.py createsuperuser
```
Follow the prompts to set a username and password.

## 5. Run the Server
Start the development server:
```bash
python manage.py runserver
```

## 6. Access the Application
Open your browser and navigate to:
[http://127.0.0.1:8000/](http://127.0.0.1:8000/)

Log in with the superuser credentials you created.

## 7. Configuration (Important!)
To use the AI Chatbot, you must configure your Google Gemini API Key:
1.  Log in to the application.
2.  Click on **Settings** in the top navigation bar.
3.  Enter your **Google Gemini API Key**.
4.  Click **Save Configuration**.

## Features Implemented
*   **Dashboard**: Overview of drift metrics.
*   **Drifts**: List and Detail views of infrastructure drifts.
    *   **Scan Now**: Simulate drift detection with the "Scan Now" button.
*   **Architecture**: Visual diagram of the network security flow.
*   **Chatbot**: Gemini-powered AI assistant widget on the Drift Detail page.
*   **Authentication**: Standard Django login/logout.
