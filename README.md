# Network Scanner

A network scanning tool for scanning IP addresses and ports in Linux and Windows systems.


## Installation
_Note: If you use Windows, instead of 'python3' use 'python'._
* Navigate to the project folder.

* Run 'pip install -r requirements.txt to install required packages.
  _Note: It's better to use virtualenv in order to avoid any conflicts in future._

* Add your env variables in .env file.

* Run the following commands one by one in a folder where you can see manage.py there:
    ```
    $ python3 manage.py makemigrations
    ```
    ```
    $ python3 manage.py migrate
    ```
* Then run the following command in that directory and answer the questions to create a superuser:
    ```
    $ python3 manage.py createsuperuser
    ```

* Finally run the following command there to start the project:
    ```
    $ python3 manage.py runserver
    ```

Now, open '_127.0.0.1:8000_' to see the project's main page.

You can see the admin panel by opening '_127.0.0.1:8000/admin_'.

