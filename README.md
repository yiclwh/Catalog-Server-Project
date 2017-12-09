# Catalog APP



## Introduction



Catalog APP is an application that provides a list of items within a variety of categories as well as provide a user registration and authentication system, all data is saved on a server database.


This APP is a **RESTful** web application using the Python framework **Flask** along with implementing third-party **OAuth** authentication. Registered users will have the ability to post, edit and delete their own items.

The project also implements **JSON** endpoints that serve the same information as displayed in the HTML endpoints for an arbitrary items in the catalog.






## Contents



* Requirements

  * Python3

  * SQLite

  * Flask

  * SQLAlchemy

  * oauth2client



* Porject files

  * `database_setup.py`

  * `preset_category.py`

  * `server.py`

  * `g_client_secrets.json`

  * `fb_client_secrets.json`

  * `README.md`

* Templates/Views

    * `categories.html`

    * `categoryitems.html`

    * `deleteCatalogItem.html`

    * `editCatalogItem.html`

    * `header.html`

    * `login.html`

    * `main.html`

    * `newCatalogItem.html`






## How To Run The Application



* Setup database scheme and preset available categories


  * First Eexcute python script `database_setup.py`


  * Then excute python script `preset_category.py`



* Bring up web server by

  
  * Excute python script `server.py`



* Go to <http://localhost:5000/> or <http://localhost:5000/catalog/>


  * By default, the web server is deployed in local machine with port 5000




## How To Run Python Script


  * Using the Terminal:


    * Type `python3 server.py` or `./server.py`



  * Using the Python IDLE:



    * Select Run from the IDLE menu,



    * Click `Run Module` from the dropdown list