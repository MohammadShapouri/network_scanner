# Network Scanner

A network scanning tool for scanning and showing IP addresses and ports and devices.


## Installation
_Note: If you use Windows, instead of 'python3' use 'python'._
* Navigate to the project's directory.

* Run 'pip install -r requirements.txt to install required packages.
  _Note: It's better to use virtualenv to avoid any conflicts in the future._

* Add your env variables in the .env file.

* Run the following commands one by one in the directory where you can see manage.py there:
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



## Screenshots
### Sessions list:
![sessions list](https://github.com/MohammadShapouri/network_scanner/blob/main/doc/list_sessions.png?raw=true)

### Creating session:
![creating session](https://github.com/MohammadShapouri/network_scanner/blob/main/doc/create_session.png?raw=true)

### Updating session:
![updating session](https://github.com/MohammadShapouri/network_scanner/blob/main/doc/update_session.png?raw=true)

### Deleting session:
![deleting session](https://github.com/MohammadShapouri/network_scanner/blob/main/doc/delete_session.png?raw=true)

### IP scan page:
![ip scan page - up](https://github.com/MohammadShapouri/network_scanner/blob/main/doc/ip_scan_page_up.png?raw=true)
![ip scan page - down](https://github.com/MohammadShapouri/network_scanner/blob/main/doc/ip_scan_page_down.png?raw=true)
