# Password Manager

A secure and user-friendly password management system built using Flask, Supabase, and JavaScript. This application allows users to register, log in, and manage their credentials securely with features like password generation, deletion, and encryption.

---

## Table of Contents

1. [Overview](#overview)
2. [Features](#features)
3. [Screenshots](#screenshots)
4. [Technologies](#technologies)
5. [Installation](#installation)
6. [Usage](#usage)
7. [Contributing](#contributing)
8. [License](#license)

---

## Overview

Password Manager is a web-based application that helps users securely store and manage their passwords. It provides a simple and clean interface for generating, saving, and retrieving strong passwords, as well as organizing different accounts securely. The application uses Flask for the backend and Supabase for database management.

---

## Features

- **User Authentication**: Sign up and log in with secure credentials.
- **Password Generation**: Automatically generate strong and secure passwords.
- **Password Management**: Store, view, and delete stored passwords for different accounts.
- **Encryption**: All passwords are encrypted to ensure security.
- **Responsive Design**: The application is mobile-friendly and looks great on all devices.

---

## Screenshots


### Dashboard

![Dashboard Screenshot](./assets/images/dashboard.png)  
*The main user dashboard where credentials are managed.*

### Login Page

![Login Screenshot](./assets/images/login.png)  
*User login page.*

You can add your images to the `assets/images/` directory, or any subfolder in your project, and update the image paths in the README to match where you save them.

---

## Technologies

- **Backend**: 
  - Python 3.11
  - Flask
  - Supabase (for remote database)
  - Flask-Login (for user session management)
  - Flask-WTF (for form handling)

- **Frontend**: 
  - HTML
  - CSS (Custom styling for clean UI)
  - JavaScript (for frontend logic)
  - jQuery (for AJAX requests)

- **Security**: 
  - Bcrypt for hashing passwords
  - SSL/TLS for secure HTTP connections

---

## Installation

To get started with the project locally, follow these steps:

### 1. Set up a Supabase Account and Database

1. **Create a Supabase Account**:
   - Go to [Supabase](https://supabase.io/) and sign up for an account.
   - Once signed in, create a new project by clicking **"New Project"**.

2. **Create a Database Table**:
   - After the project is created, go to the **SQL Editor** section and create the necessary tables for your app. Here's an example SQL script for creating the user and passwords tables:
   
     ```sql
     create table users (
         id serial primary key,
         email text not null unique,
         password_hash text not null,
         created_at timestamp with time zone default now()
     );

     create table passwords (
         id serial primary key,
         user_id integer references users(id) on delete cascade,
         account_name text not null,
         password_hash text not null,
         created_at timestamp with time zone default now()
     );
     ```

3. **Get your Supabase `database_url`**:
   - Go to the **Settings** page of your Supabase project.
   - In the **API** section, find the `database_url` under the **Connection Info**.
   - Copy the `database_url` (it will look something like: `postgres://user:password@host:port/database`).

4. **Set up Supabase in your Application**:
   - You'll need to connect your Flask app to Supabase using the `database_url` you copied. Save this URL securely.

### 2. Configure the Application Locally

1. **Clone this repository** to your local machine:

   ```bash
   git clone https://github.com/Arkoto-Tech/pmanager.git
   cd password-manager
   
2. **Create and activate a virtual enviroment**:

   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows, use `venv\Scripts\activate`

3. **Install required dependencies**:

   ```bash
   pip install -r requirements.txt

4. **Create a `.env` file in the project root to store your sensitive data like the `database_url`**:

   ```bash
   touch .env
Add the following content to the `.env` file, replacing `<your-database-url>` with the `database_url` you copied from Supabase:
   ```ini
   DATABASE_URL=<your-database-url>
   FLASK_ENV=development
   ```
5. **Set up the database**:
   - Supabase is a managed PostgreSQL database, so the app should work out of the box without requiring manual table migrations, as long as you already set up the tables via Supabase SQL Editor.

6. **Run the application locally**:

   ```bash
   flask run

The app should now be running at http://127.0.0.1:5000/. You can access the website in your browser.

## Usage
1. Sign up: Go to the Sign-up page to create a new account. Enter your details, and click on "Sign Up."

2. Log in: After signing up, go to the Login page to log in with your new account.

3. Dashboard: Once logged in, you will be redirected to your dashboard where you can manage your credentials. Use the options to add, view, or delete your stored passwords.

4. Password Generation: On the dashboard, use the "Generate Password" button to generate a strong password for any account you need.


## Contributing
We welcome contributions to improve the project! To contribute:

1. Fork this repository.

2. Create a new branch for your feature or bug fix.

3. Make your changes and commit them with clear messages.

4. Push your branch to your forked repository.

5. Open a pull request to the main repository with a description of the changes.

Please ensure that your code follows the project’s style guide and passes all tests.
