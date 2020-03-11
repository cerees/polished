



#' Sessions
#'
#' R6 class to track the polished sessions
#'
#' @export
#'
#' @importFrom R6 R6Class
#' @importFrom httr GET content warn_for_status
#' @importFrom jsonlite fromJSON
#' @importFrom digest digest
#' @importFrom DBI dbGetQuery dbWithTransaction dbExecute dbIsValid
#' @importFrom jose jwt_decode_sig
#' @importFrom lubridate with_tz minutes
#'
Sessions <-  R6::R6Class(
  classname = 'Sessions',
  public = list(
    app_name = character(0),
    conn = NULL,
    firebase_project_id = NULL,
    # Session configuration function.  This must be executed in global.R of the Shiny app.
    #
    # @param app_name the name of the app
    # @param firebase_project_id the project ID for the Firebase project
    # @param conn the database connection
    # @param authorization_level whether the app should be accessible to "all" users in the
    # "polished.users" table, or if it should only be accessible to users as defined in the
    # "app_users" table. Valid options are "app" or "all".  Defaults to "app".
    #
    config = function(
      app_name,
      firebase_project_id = NULL,
      conn = NULL,
      authorization_level = 'app'
    ) {
      if (!(length(firebase_project_id) == 1 && is.character(firebase_project_id))) {
        stop("invalid `firebase_project_id` argument passed to `global_sessions_config()`", call. = FALSE)
      }
      if (!(length(app_name) == 1 && is.character(app_name))) {
        stop("invalid `app_name` argument passed to `global_sessions_config()`", call. = FALSE)
      }
      if (!(length(authorization_level) == 1 && is.character(authorization_level))) {
        stop("invalid `authorization_level` argument passed to `global_sessions_config()`", call. = FALSE)
      }
      tryCatch({
        if (!DBI::dbIsValid(conn)) {
          stop("invalid `conn` argument passed to `global_sessions_config()`", call. = FALSE)
        }
      }, error = function(err) {
        stop("invalid `conn` argument passed to `global_sessions_config()`", call. = FALSE)
      })


      self$app_name <- app_name
      self$conn <- conn
      private$authorization_level <- authorization_level
      self$firebase_project_id <- firebase_project_id

      private$refresh_jwt_pub_key()

      invisible(self)
    },
    # the current time + 1 minute.  Used to check that the keys have not
    # expired.  Using time of 1 minute into the future to be safe.
    curr_time_1 = function() {
      lubridate::with_tz(Sys.time(), tzone = "UTC") + lubridate::minutes(1)
    },
    #' @description
    #' returns either the signed in user if the sign in is successfull or NULL
    #' if the sign in fails.
    #'
    #' @param firebase_token the id token JWT created by the Firebase client side
    #' JavaScript.
    #' @param hashed_cookie the hashed polished cookie
    #'
    #' @return a list containing the collofing if sign in is successful:
    #' - is_admin
    #' - $is_admin
    #' - user_uid
    #' - roles
    #'
    #' roles_out the sign in is successful this function also executed `private$add(<user session>)`
    #' which inserts the newly activated session into the "polished.sessions" table.
    #'
    sign_in = function(firebase_token, hashed_cookie) {

      decoded_jwt <- NULL
      tryCatch({

        # check if the jwt public key has expired.
        curr_time <- self$curr_time_1()
        if (curr_time > private$jwt_pub_key_expires) {
          private$refresh_jwt_pub_key()
        }

        decoded_jwt <- private$verify_firebase_token(firebase_token)

      }, error = function(e) {
        print('[polished] error signing in')
        print(e)
      })


      new_session <- NULL

      if (!is.null(decoded_jwt)) {

        new_session <- list(
          email = decoded_jwt$email,
          firebase_uid = decoded_jwt$user_id,
          email_verified = decoded_jwt$email_verified
        )

        tryCatch({
          # confirm that user is invited
          invite <- self$get_invite_by_email(new_session$email)

          # find the users roles
          roles_out <- self$get_roles(invite$user_uid)

          new_session$is_admin <- invite$is_admin
          new_session$user_uid <- invite$user_uid
          new_session$roles <- roles_out

        }, error = function(e) {

          print(e)
          new_session <<- NULL
        })



        new_session$hashed_cookie <- hashed_cookie

        # TODO: automaticlaly generate this in postgres
        new_session$session_uid <- create_uid()
        # add the session to the 'sessions' table
        private$add(new_session)
      }

      dbExecute(
        self$conn,
        "INSERT INTO polished.session_actions (uid, session_uid, action) VALUES ($1, $2, $3)",
        list(
          create_uid(),
          new_session$session_uid,
          'sign_in'
        )
      )

      return(new_session)
    },
    get_invite_by_email = function(email) {

      invite <- NULL
      DBI::dbWithTransaction(self$conn, {

        user_db <- DBI::dbGetQuery(
          self$conn,
          "SELECT * FROM polished.users WHERE email=$1",
          params = list(
            email
          )
        )

        if (nrow(user_db) != 1) {
          stop(sprintf('unable to find "%s" in "users" table', email))
        }

        invite <- self$get_invite_by_uid(user_db$uid)
      })

      return(invite)
    },
    get_invite_by_uid = function(user_uid) {

      if (private$authorization_level == "app") {
        # authorization for this user is set at the Shiny app level, so only check this specific app
        # to see if the user is authorized
        invite <- DBI::dbGetQuery(
          self$conn,
          "SELECT * FROM polished.app_users WHERE user_uid=$1 AND app_name=$2",
          params = list(
            user_uid,
            self$app_name
          )
        )
      } else if (private$authorization_level == "all") {
        # if user is authoized to access any apps, they can access this app.
        # e.g. used for apps_dashboards where we want all users that are allowed to access any app to
        # be able to access the dashboard.
        invite <- DBI::dbGetQuery(
          self$conn,
          "SELECT * FROM polished.app_users WHERE user_uid=$1 LIMIT 1",
          params = list(
            user_uid
          )
        )
      }

      if (nrow(invite) != 1) {
        stop(sprintf('user "%s" is not authorized to access "%s"', user_uid, self$app_name))
      }

      invite
    },
    # return a character vector of the user's roles
    get_roles = function(user_uid) {
      roles <- character(0)
      DBI::dbWithTransaction(self$conn, {

        role_names <- DBI::dbGetQuery(
          self$conn,
          "SELECT uid, name FROM polished.roles WHERE app_name=$1",
          params = list(
            self$app_name
          )
        )

        role_uids <- DBI::dbGetQuery(
          self$conn,
          "SELECT role_uid FROM polished.user_roles WHERE user_uid=$1 AND app_name=$2",
          params = list(
            user_uid,
            self$app_name
          )
        )$role_uid

        roles <- role_names %>%
          dplyr::filter(uid %in% role_uids) %>%
          dplyr::pull(name)
      })

      roles
    },
    find = function(hashed_cookie) {

      signed_in_sessions <- dbGetQuery(
        self$conn,
        'SELECT uid AS session_uid, user_uid, email, email_verified, firebase_uid,
        app_name, signed_in_as FROM polished.sessions WHERE hashed_cookie=$1 AND
        is_signed_in=$2',
        params = list(
          token,
          TRUE
        )
      )

      session_out <- NULL
      if (nrow(signed_in_sessions) > 0) {



        # confirm that user is invited
        invite <- self$get_invite_by_uid(signed_in_sessions$user_uid[1])
        roles <- self$get_roles(signed_in_sessions$user_uid[1])

        app_session <- signed_in_sessions %>%
          filter(.data$app_name == self$app_name)

        # if user is not invited, the above `get_invite_by_uid()` function will throw an error.  If user is invited,
        # return the user session


        session_out <- list(
          "user_uid" = signed_in_sessions$user_uid[1],
          "email" = signed_in_sessions$email[1],
          "firebase_uid" = signed_in_sessions$firebase_uid[1],
          "email_verified" = signed_in_sessions$email_verified[1],
          "is_admin" = invite$is_admin,
          "roles" = roles,
          "hashed_cookie" = hashed_cookie
        )


        if (nrow(app_session) == 0) {
          # user was signed into another app and came over to this app, so add a session for this app
          session_out$session_uid <- create_uid()

          private$add(session_out)
          session_out$signed_in_as <- NA
        } else if (nrow(app_session) == 1) {

          session_out$session_uid <- app_session$session_uid
          session_out$signed_in_as <- app_session$signed_in_as
        } else {
          stop('error: too many sessions')
        }
      }

      return(session_out)
    },
    list = function() {

      out <- dbGetQuery(
        self$conn,
        "SELECT * FROM polished.active_sessions"
      )

      return(out)
    },
    refresh_email_verification = function(session_uid, firebase_token) {

      email_verified <- NULL
      tryCatch({

        # check if the jwt public key has expired.  Add an extra minute to the
        # current time for padding before checking if the key has expired.
        curr_time <- curr_time_1()
        if (curr_time > private$jwt_pub_key_expires) {
          private$refresh_jwt_pub_key()
        }

        decoded_jwt <- private$verify_firebase_token(firebase_token)

        if (!is.null(decoded_jwt)) {
          email_verified <- decoded_jwt$email_verified
        }

      }, error = function(e) {
        print('[polished] error signing in')
        print(e)
      })

      if (is.null(email_verified)) {
        stop("email verification user not found")
      } else {
        dbExecute(
          self$conn,
          'UPDATE polished.sessions SET email_verified=$1 WHERE uid=$2',
          params = list(
            email_verified,
            session_uid
          )
        )
      }


      invisible(self)
    },

    #' @description
    #' sign in as an alternate user
    #'
    #' @param session_uid the session uid
    #' @param signed_in_as_user_uid the user uid of the user to that the admin is
    #' signing in as.
    set_signed_in_as = function(session_uid, signed_in_as_user_uid) {

      dbExecute(
        self$conn,
        'UPDATE polished.sessions SET signed_in_as=$1 WHERE session_uid=$2',
        params = list(
          signed_in_as$uid,
          session_uid
        )
      )

      invisible(self)
    },
    clear_signed_in_as = function(session_uid) {

      dbExecute(
        self$conn,
        'UPDATE polished.sessions SET signed_in_as=$1 WHERE session_uid=$2',
        params = list(
          NA,
          session_uid
        )
      )

      invisible(self)
    },
    get_signed_in_as_user = function(user_uid) {

      email <- dbGetQuery(
        self$conn,
        'SELECT email FROM polished.users WHERE uid=$1',
        list(
          user_uid
        )
      )$email

      invite <- self$get_invite_by_uid(user_uid)

      roles <- self$get_roles(user_uid)

      list(
        user_uid = user_uid,
        email = email,
        is_admin = invite$is_admin,
        roles = roles
      )
    },


    #' @description
    #' set the user session to active
    #'
    #' @param session_uid the session uid
    #'
    #' @details This function sets "is_active" to `FALSE` for the session uid in the
    #' polished.sessions table.  We execute this function when the user disconnects
    #' from the custom Shiny app that is using polished.
    #'
    set_inactive = function(session_uid) {

      DBI::dbWithTransaction(self$conn, {

        DBI::dbExecute(
          self$conn,
          'UPDATE polished.sessions SET is_active=$1 WHERE uid=$2',
          list(
            FALSE,
            session_uid
          )
        )

        DBI::dbExecute(
          self$conn,
          "INSERT INTO polished.session_actions (uid, session_uid, action) VALUES ($1, $2, $3)",
          list(
            create_uid(),
            session_uid,
            'deactivate'
          )
        )

      })

    },


    #' @description
    #' set the user session to active
    #'
    #' @param session_uid the session uid
    #'
    #' @details this function sets "is_active" to TRUE in the "polished.sessions"
    #' table.  This occurs when a user returns to the Shiny app and they are still
    #' signed in from a previous session.
    #'
    set_active = function(session_uid) {


      DBI::dbWithTransaction(self$conn, {


        DBI::dbExecute(
          self$conn,
          'UPDATE polished.sessions SET is_active=$1 WHERE uid=$2',
          list(
            TRUE,
            session_uid
          )
        )

        DBI::dbExecute(
          self$conn,
          "INSERT INTO polished.session_actions (uid, session_uid, action) VALUES ($1, $2, $3)",
          list(
            create_uid(),
            session_uid,
            'activate'
          )
        )
      })

    },



    #' @description
    #' sign the user out of all sessions in the polished project
    #'
    #' @details
    #' if this project has more than 1 polished app and/or the user is signed into
    #' app(s) in thie polished project from more than 1 device, the user can have more
    #' than 1 active session.  This function signs the user out of all active sessions.
    #'
    #' @param user_uid the uid of the user
    sign_out = function(user_uid) {

      DBI::dbWithTransaction(self$conn, {

        # get all signed in session.  Note: a session can have "is_active"=FALSE but still
        # have "is_signed_in"=TRUE because once they end their Shiny session, "is_active" is
        # set to FALSE, but "is_signed_in" is still TRUE.
        active_session_uids <- DBI::dbGetQuery(
          self$conn,
          'SELECT session_uid FROM polished.sessions WHERE user_uid=$1 AND is_signed_in=$2'
        )$session_uid

        if (length(active_session_uids) == 0) {
          print('[polished] no signed in sessions')
          return(NULL)
        }

        # set all active sessions to inactive and sign out
        DBI::dbExecute(
          self$conn,
          'UPDATE polished.sessions SET is_active=$1, is_signed_in=$2 WHERE user_uid=$3 AND is_signed_in=$4',
          list(
            FALSE,
            FALSE,
            user_uid,
            TRUE
          )
        )

        # create a sign_out action for all sessions that the user just ended
        for (active_session_uid in seq_along(active_session_uids)) {

          DBI::dbExecute(
            self$conn,
            "INSERT INTO polished.session_actions (uid, session_uid, action) VALUES ($1, $2, $3)",
            list(
              create_uid(),
              active_session_uid,
              'sign_out'
            )
          )

        }

      })

    }
  ),
  private = list(
    add = function(session) {

      dbExecute(
        self$conn,
        'INSERT INTO polished.sessions (uid, user_uid, firebase_uid, email, email_verified, token, app_name) VALUES ($1, $2, $3, $4, $5, $6, $7)',
        list(
          session$session_uid,
          session$user_uid,
          session$firebase_uid,
          session$email,
          session$email_verified,
          session$token,
          self$app_name
        )
      )

      invisible(self)
    },


    # polished configuration setting.
    # valid values a "app" or "all".  "app" means that users authorized to access this
    # app are only otherized to access this app.  "all" means that all users authoized to
    # access any apps in this polished project can access this app.
    authorization_level = "app", # or "all"


    pub_keys = NULL,
    # number of seconds that the public key will remain valid
    pub_keys_expires = NULL,


    #' @desciption
    #' refresh public keys
    #'
    #' @description
    #' These keys are used to verify the user's firebase token when the user signs
    #' in to polished.  If the public keys are successfully returned from Google, this
    #' function set them to `private$pub_keys` and updates `privet$pub_keys_expire`.
    #' If unsuccessful throw an error.
    #'
    refresh_pub_keys = function() {
      # get the public keys from Google
      pub_keys_resp <- httr::GET("https://www.googleapis.com/robot/v1/metadata/x509/securetoken@system.gserviceaccount.com")

      # Error if we didn't get the keys successfully
      httr::stop_for_status(pub_keys_resp)

      # key response successful, so set the `pub_keys` property
      private$pub_keys <- jsonlite::fromJSON(
        httr::content(pub_keys_resp, "text")
      )


      # Decode the expiration time of the keys from the Cache-Control header
      cache_controls <- httr::headers(google_keys_resp)[["Cache-Control"]]
      if (!is.null(cache_controls)) {
        cache_control_elems <- strsplit(cache_controls, ",")[[1]]
        split_equals <- strsplit(cache_control_elems, "=")
        for (elem in split_equals) {

          if (length(elem) == 2 && trimws(elem[1]) == "max-age") {
            max_age <- as.numeric(elem[2])
            private$pub_keys_expire <- lubridate::with_tz(Sys.time(), tzone = "UTC") + max_age
            break
          }

        }
      }
    },



    #' @description
    #' verify the Firebase id token
    #'
    #' @details
    #' Verify the firebase token using the methodology outlined here
    #' \url{https://firebase.google.com/docs/auth/admin/verify-id-tokens}
    #'
    #' @param firebase_token this the JWT created by the Firebase client side
    #' Javascript
    #'
    #' @return if `firebase_token` successfully verified, a list containing the users
    #' Firebase user information, or an error if unsuccessful.
    #'
    verify_firebase_token = function(firebase_token) {
      # Google sends us 2 public keys to authenticate the JWT.  Sometimes the correct
      # key is the first one, and sometimes it is the second.  I do not know how
      # to tell which key is the right one to use, so we try them both for now.
      decoded_jwt <- NULL
      for (key in private$pub_keys) {
        # If a key isn't the right one for the token, then we get an error.
        # Ignore the errors and just don't set decoded_token if there's
        # an error. When we're done, we'll look at the the decoded_token
        # to see if we found a valid key.
        try({
          decoded_jwt <- jose::jwt_decode_sig(firebase_token, key)
          break
        }, silent=TRUE)
      }

      if (is.null(decoded_jwt)) {
        stop("[polished] error decoding Firebase token")
      }

      curr_time <- lubridate::with_tz(Sys.time(), tzone = "UTC")
      # Verify the ID token
      # https://firebase.google.com/docs/auth/admin/verify-id-tokens
      if (!(as.numeric(decoded_jwt$exp) > curr_time &&
            as.numeric(decoded_jwt$iat) < curr_time &&
            as.numeric(decoded_jwt$auth_time) < curr_time &&
            decoded_jwt$aud == self$firebase_project_id &&
            decoded_jwt$iss == paste0("https://securetoken.google.com/", self$firebase_project_id) &&
            nchar(decoded_jwt$sub) > 0)) {

        stop("[polished] error verifying JWT")
      }

      decoded_jwt
    }
  )
)

.global_sessions <- Sessions$new()




