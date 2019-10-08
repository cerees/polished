"use strict";

var auth = firebase.auth();

var sign_in = function sign_in(email, password) {
  return auth.signInWithEmailAndPassword(email, password).then(function (user) {
    console.log("user: ", user);
    var polished_token = Cookies.get("polished__token");
    return user.user.getIdToken(true).then(function (firebase_token) {
      Shiny.setInputValue("polished__sign_in", {
        firebase_token: firebase_token,
        polished_token: polished_token
      }, {
        event: "priority"
      });
    });
  });
};

var auth_firebase = function auth_firebase(ns_id) {
  var ns = NS(ns_id);
  $(document).on("click", ns("submit_register"), function () {
    var email = $(ns("register_email")).val().toLowerCase();
    var password = $(ns("register_password")).val();
    var password_2 = $(ns("register_password_verify")).val();

    if (password !== password_2) {
      //toastr.error("The passwords do not match")
      console.log("the passwords do not match");
      return;
    }

    $.LoadingOverlay("show", loading_options); // double check that the email is in "invites" collection

    auth.createUserWithEmailAndPassword(email, password).then(function (userCredential) {
      // send verification email
      return userCredential.user.sendEmailVerification()["catch"](function (error) {
        console.error("Error sending email verification", error);
      });
    }).then(function () {
      return sign_in(email, password)["catch"](function (error) {
        $.LoadingOverlay("hide");
        toastr.error("Sign in Error: " + error.message);
        console.log("error: ", error);
      });
    })["catch"](function (error) {
      //toastr.error("" + error)
      $.LoadingOverlay("hide");
      console.log("error registering user");
      console.log(error);
    });
  });
  $(document).on("click", ns("reset_password"), function () {
    var email = $(ns("email")).val().toLowerCase();
    auth.sendPasswordResetEmail(email).then(function () {
      console.log("Password reset email sent to ".concat(email)); //toastr.success("Password reset email sent to " + email)
    })["catch"](function (error) {
      //toastr.error("" + error)
      console.log("error resetting email: ", error);
    });
  });
  $(document).on("click", ns("submit_sign_in"), function () {
    $.LoadingOverlay("show", loading_options);
    var email = $(ns("email")).val().toLowerCase();
    var password = $(ns("password")).val();
    sign_in(email, password)["catch"](function (error) {
      $.LoadingOverlay("hide");
      toastr.error("Sign in Error: " + error.message);
      console.log("error: ", error);
    });
  });
};