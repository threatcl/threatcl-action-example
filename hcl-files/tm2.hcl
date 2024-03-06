 spec_version = "0.1.6"

 threatmodel "Modelly model" {
   imports = ["control-library/othercontrols.hcl"]
   author = "@xntrik"

   threat {
     description = "threaty threat"
     expanded_control "control name" {
      description = import.control.control_name.description
      risk_reduction = 40
     }
     stride = ["Spoofing", "Elevation of privilege"]
   }

   data_flow_diagram {
     external_element "Google Analytics" {}

     process "Client" {
       trust_zone = "Browser"
     }

     flow "https" {
       from = "Client"
       to = "Google Analytics"
     }

     process "Web Server" {
       trust_zone = "AWS"
     }

     data_store "Logs" {
       trust_zone = "AWS"
     }

     flow "TCP" {
       from = "Web Server"
       to = "Logs"
     }

     data_store "sqlite" {
       trust_zone = "AWS"
     }

     flow "https" {
       from = "Client"
       to = "Web Server"
      }

      flow "https" {
        from = "Web Server"
        to = "sqlite"
      }

      flow "https" {
        from = "sqlite"
        to = "Web Server"
      }
   
   }

 }
