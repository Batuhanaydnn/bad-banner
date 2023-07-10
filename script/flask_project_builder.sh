#!/bin/bash

directories=(
    "app/models"
    "app/views"
    "app/controllers"
    "app/services"
    "app/templates"
    "app/static/css"
    "app/static/js"
    "migrations"
    "tests"
    "scripts"
    "docs"
)

files=(
    "app/__init__.py"
    "app/models/__init__.py"
    "app/models/user.py"
    "app/views/__init__.py"
    "app/views/auth.py"
    "app/controllers/__init__.py"
    "app/controllers/user_controller.py"
    "app/services/__init__.py"
    "app/services/user_service.py"
    "app/templates/base.html"
    "app/templates/index.html"
    "app/static/css/style.css"
    "app/static/js/script.js"
    "app.py"
    "config.py"
    "requirements.txt"
)

for dir in "${directories[@]}"
do
    mkdir -p "$dir"
done

# Dosyaları oluştur
for file in "${files[@]}"
do
    touch "$file"
done

echo "Yapı başarıyla oluşturuldu."
