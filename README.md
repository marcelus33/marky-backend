## PostGIS Setup

1. **Install system dependencies**  
   ```bash
   sudo apt-get install binutils gdal-bin libgdal-dev
   ```
   
2.**Configure Django**  
   ```
INSTALLED_APPS += [
    'django.contrib.gis',
    # … other apps …
]

DATABASES = {
    'default': {
        'ENGINE': 'django.contrib.gis.db.backends.postgis',
        'NAME': '<your_database>',
        'USER': '<your_user>',
        'PASSWORD': '<your_password>',
        'HOST': '<your_host>',
        'PORT': '<your_port>',
    }
}
   ```
3.**Enable PostGIS extension** 

```
sudo -i -u postgres
psql -d <your_database>
CREATE EXTENSION IF NOT EXISTS postgis;
\q
exit
```