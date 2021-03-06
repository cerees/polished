#' verify email page ui
#'
#' @param id the Shiny module id
#' @param firebase_config Firebase configuration
#'
#' @importFrom htmltools tags h1
#' @importFrom shiny fluidPage fluidRow column
#' @importFrom shinytoastr useToastr
#'
#' @export
verify_email_module_ui <- function(id, firebase_config) {
  ns <- NS(id)

  fluidPage(
    tags$head(
      tags$link(rel = "stylesheet", href = "polish/css/all.css"),
      tags$link(rel = "shortcut icon", href = "polish/images/tychobra-icon-blue.png")
    ),
    shinytoastr::useToastr(),
    fluidRow(
      column(
        12,
        class = "text-center",
        style = "margin-top: 150px",
        h1("Verification Email Sent"),
        tags$button(
          class = "btn btn-default action-button",
          id = "resend_verification_email",
          "Resend Verification Email"
        )
      )
    ),
    firebase_dependencies(),
    firebase_init(firebase_config),
    tags$script(src = "polish/js/toast_options.js"),
    tags$script(src = "polish/js/verify_email_module.js"),
    tags$script(paste0("verify_email_module('", ns(''), "')"))
  )
}


#' verify email page ui
#'
#' @param input the Shiny server input
#' @param output the Shiny server output
#' @param session the Shiny server session
#'
#' @importFrom shiny observeEvent
#'
#' @export
#'
#'
verify_email_module <- function(input, output, session) {


  shiny::observeEvent(input$refresh_email_verification, {

    tryCatch({

      .global_sessions$refresh_email_verification(
        session$userData$user()$session_uid,
        input$refresh_email_verification
      )

    }, error = function(err) {
      sign_out_from_shiny(session)

      print("[polished] error - refreshing email verification")
      print(err)
    })

    session$reload()

  })

}
