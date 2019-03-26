#!/bin/bash
find . -type f | grep ".pyc$" | xargs rm
./manage.py runserver 0.0.0.0:8000
