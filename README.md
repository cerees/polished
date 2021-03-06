# polished <img src="inst/assets/images/polished_hex.png" align="right" width="120" />

[![Lifecycle:
maturing](https://img.shields.io/badge/lifecycle-maturing-blue.svg)](https://www.tidyverse.org/lifecycle/#maturing) [![Travis-CI Build Status](https://travis-ci.org/Tychobra/polished.svg?branch=master)](https://travis-ci.org/tychobra/polished)

Authentication and user administration for Shiny apps.  `polished` provides a way to secure your Shiny application behind an authentication layer.  It also provides a UI for controlling user access. 

Sign in to a [Live Demo Shiny App](https://tychobra.shinyapps.io/polished_example_01) with the following:

 - email: demo@tychobra.com
 - password: polished

Check out the [introducing polished blog post](https://www.tychobra.com/posts/2019_08_27_announcing_polished/) for a high level overview and video.

Warning: there will be many breaking changes before this package matures to version 1.0.0

### Requirements

- R
- one or more Shiny apps
- a [Firebase](https://firebase.google.com/) account
- a PostgreSQL database

### `polished` installation

```
# R

remotes::install_github("tychobra/tychobratools")
remotes::install_github("tychobra/polished")
```

### Initial Set Up

1. Set up your Firebase project. Go to [https://firebase.google.com/](https://firebase.google.com/) and create a firebase project named "polished-<project_name>".  Open your new Firebase project and:
   - go to the "Authentication" page "Sign-in method" tab and enable "Email/Password" sign in. See the below screenshot:
   ![](https://res.cloudinary.com/dxqnb8xjb/image/upload/v1573001859/firabse-auth_roq6yv.png)

2. Set up PostgreSQL "polished" schema.  This schema stores your users, apps, and information about which users are authorized to access which apps.  To create this schema you must have a PostgreSQL database that you can connect to.

```
# R

# connect to your PostgreSQL database
db_conn <- DBI::dbConnect(
  RPostgres::Postgres(),
  <your db connection credentials>
)

# If this is your first Shiny app using polished, create the "polished" schema.
# Warning: if you already have a polished schema this function will overwrite your existing schema with empty tables.
polished::create_schema(db_conn)
```

3. Secure Your Shiny App

Get the following credentials from your Firebase project: 
  - apiKey
  - authDomain
  - projectId
  
**NOTE:** To find `authDomain`, click on the `Add Web App` button at the bottom of General Settings (shown in the screenshot below). Register the App (do NOT need to check box for "Also set up Firebase Hosting for this app") & back at the bottom of the General Settings page where the "Add Web App" button was, you'll see the app just added. You'll find `authDomain` under the 'Firebase SDK snippet' section.  

<img src="inst/assets/images/add_web_app.png" />
  
These Firebase credentials can be found on the "Project settings" page of your Firebase project at console.firebase.google.com.

Then you will need to execute the `global_sessions_config()` in "global.R", pass your Shiny ui to `secure_ui()`, and your Shiny server to `secure_server()`.  See the documentation of `global_sessions_config()`, `secure_ui()`, and `secure_server()` for details. 

4. Invite the first user to your app

At this point, when you run your app you should see the sign in page. e.g:

<p align="center">
 <img src="https://res.cloudinary.com/dxqnb8xjb/image/upload/v1584201376/Screen_Shot_2020-03-14_at_11.55.40_AM_vxmnds.png"/>
</p>

But, if you enter your email and click "Continue", you will see a "Not Authorized -
You must have an invite to access this app" alert.  By default polished requires users to first be invited before they can access your app.

You can invite yourself (and other users) to access your app by running the app locally in "admin_mode".  To run the app in "admin_mode", set the "admin_mode" argument of `global_sessions_config()` to `TRUE` and restart your R session (make sure to set the "admin_mode" argument back to `FALSE` before you deploy your app!).  When you run your Shiny app in "admin_mode" you will be taken directly to the polished Admin Panel without having to sign in.  You can then go to the "User Access" tab to invite users.  e.g.

<img src="https://res.cloudinary.com/dxqnb8xjb/image/upload/v1584199811/user_access_issvjz.png"/>

Enter the email address of the user you want to invite to your app.  

![](https://res.cloudinary.com/dxqnb8xjb/image/upload/v1584199960/Screen_Shot_2020-03-14_at_11.31.45_AM_owpdqh.png)

If you set the "Is Admin?" radio button to "Yes", the user will have access to
your Shiny app and the `polished` Admin Panel (i.e. the user will be able to invite additional
users and remove existing user from your app).  If "Is Admin?" if set to "No", the user will
be able to access your Shiny app, but they will __not__ have access to the `polished` Admin Panel; non admins are not authorized to invite/remove users.

Once the user has been added, restart the app & register the new user on the Polished login page. You'll be redirected to a page which says that user has received an email invitation for registration. Once the link in the email has been clicked, the app can be refreshed and that user is able to sign in!

You can find a few full working example in the "inst/examples/" directory in this package.  

### Additional Options

#### 1. Customize the Sign In / Register UI

Companies often want to add their logos and branding to the sign in and register pages.  With polished, you can easily customize these pages.  Just pass your custom UI to the `sign_in_page_ui` argument of `secure_ui()`.  

Sign in to a [Live Example](https://tychobra.shinyapps.io/custom_sign_in) with the following:

 - email: demo@tychobra.com
 - password: polished

The code for the above example is available in the "inst/examples/custom_sign_in/" directory.  To get this example working, you will need to update the "config.yml" with your Firebase credentials. 

#### 2. Do not require invite for sign in / register

Allow anyone to register and sign in to your app (i.e. no invite required).  See the code of a simple example in "inst/examples/no_invite_required" and the [live demo here](https://tychobra.shinyapps.io/custom_sign_in). 

#### 3. Add custom tabs to the Polished Admin shinydashboard

You can add custom tabs to the admin dashboard by passing the ui and server code to the `secure_ui()` and `secure_server()` functions.  Example coming soon.

#### 4. Apps Dashboard

Create a Shiny dashboard of your Shiny dashboards/apps.  Example coming soon.

