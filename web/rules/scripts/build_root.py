import os
import sys
import yaml
import random
from datetime import datetime, timedelta


start_dir = sys.argv[1]
txt_file_path = sys.argv[2]
out_dir = sys.argv[3]
output_html_path = os.path.join(out_dir, 'index.html')

assert os.path.exists(start_dir), "input directory must exist"
assert os.path.exists(txt_file_path), "file-modification txt file must exist"
assert os.path.exists(out_dir), "output directory must exist"

predefined_colors = [
    "#9CAFAA", "#577590", "#a98467", "#D6DAC8", "#adc178",
    "#f4d35e", "#85182a", "#d6c399", "#dde5b6", "#8da9c4",
    "#fcd5ce", "#706993", "#FBF3D5", "#1a659e", "#c71f37",
    "#EFBC9B", "#7e7f9a"
]

def read_file_paths(txt_file_path):
    categorized_files = {
        "modified in the last day": [],
        "modified in the last week": [],
        "modified in the last month": [],
        "modified in the last three months": [],
        "modified in the last year": [],
        "older": [],
    }

    with open(txt_file_path, 'r') as f:
        lines = f.readlines()

    current_category = None
    for line in lines:
        line = line.strip()
        if not line:
            continue
        if '===' in line:
            category = line.strip('===').strip()
            if category in categorized_files:
                current_category = category
            else:
                print(f"Warning: Unrecognized category '{category}'")
                current_category = None
        elif current_category:
            parts = line.split(' ', 1)
            if len(parts) == 2:
                file_path, last_modified_date_str = parts
                try:
                    last_modified_date = datetime.strptime(last_modified_date_str, '%Y-%m-%d %H:%M:%S')
                    categorized_files[current_category].append(file_path)
                except ValueError:
                    print(f"Error parsing date for file {file_path}: {last_modified_date_str}")
            else:
                print(f"Warning: Skipping line due to unexpected format: {line}")

    return categorized_files


def parse_yaml(file_path):
    with open(file_path, 'r') as f:
        data = yaml.safe_load(f)
    meta = data.get('rule', {}).get('meta', {})
    name = meta.get('name', 'N/A')
    namespace = meta.get('namespace', 'N/A')
    authors = ', '.join(meta.get('authors', []))
    return {
        'name': name,
        'namespace': namespace,
        'authors': authors
    }

def generate_color():
    return "#{:06x}".format(random.randint(0, 0xFFFFFF))

def get_first_word(namespace):
    return namespace.split('/')[0] if '/' in namespace else namespace

def generate_html(categories_data, color_map):
    html_content = '''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>capa rules</title>
    <link rel="stylesheet" href="./pagefind/pagefind-ui.css">
    <link rel="stylesheet" href="./pagefind/pagefind-modular-ui.css">
    <link href="./pagefind/pagefind-ui.css" rel="stylesheet">
    <link href="./css/poppins.css" rel="stylesheet">
    <link href="./css/bootstrap-5.3.3.min.css" rel="stylesheet">
    <link rel="icon" href="./img/favicon.png" type="image/x-icon"> <!-- Favicon -->
    <script src="./pagefind/pagefind-ui.js"></script>
    <style>
         body {
            background-color: #ffffff;
            font-family: 'Poppins', sans-serif;
            margin: 0;
            padding: 0;
        }

        .container-fluid {
            padding: 0 40px; 
        }

        .row {
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 10px; 
        }

        .card-wrapper {
            display: flex;
            align-items: stretch; 
        }

        .card {
            background-color: #FFFFFF;
            border-radius: 10px;
            box-shadow: 0px 0px 0px 0px #E5EDFF;
            padding: 10px;
            transition: box-shadow 0.3s ease-in-out;
            display: flex;
            flex-direction: column;
            width: 100%; 
        }

        .card:hover {
            box-shadow: 10px 10px 0px 0px #E5EDFF;
        }

        .thin-rectangle {
            width: 15px;
            height: 40px;
            position: absolute;
            top: 20px;
            left: 0;
        }

        .namespace {
            color: grey;
            font-weight: bold;
            font-size: 13px;
        }

        .rule-name {
            color: black;
            font-weight: bold;
            font-size: 14.5px;
        }

        .authors {
            color: black;
            font-size: 13px;
        }

        .tags {
            margin-top: 10px;
        }

        .tag {
            background-color: hsl(210, 98%, 80%);
            border: none;
            border-radius: 20px;
            color: black;
            font: 600 1.05rem/1 "Poppins", sans-serif;
            padding: 0.5em 1.5em;
            margin-right: 5px;
            display: inline-block;
            font-size: 12px;
            text-transform: lowercase;
            transition: transform 0.3s;
        }

        .tag:hover {
            transform: scale(1.1);
        }

        .card-body {
            flex: 1;
        }

        a {
            color: inherit;
            text-decoration: none;
        }

        a:hover {
            text-decoration: underline;
        }

    
        .navbar {
            width: 100%;
            max-width: 100%;
        }

        .navbar-brand img {
            width: 78px; 
            height: 42px; 
        }

        .hero-image {
            width: 100%;
            max-width: 100%;
            height: auto;
            margin-top: 10px;
            margin-left: -40px; 
        }
    </style>
    </style>
</head>
<body>
    <nav class="navbar navbar-light bg-light">
        <a class="navbar-brand" href="#">
            <img src="./img/logo.png" width="30" height="30" alt="Logo">
        </a>
        <div id="search"></div>
    </nav>
    <div class="container-fluid">
        <img src="./img/HeroImage.png" alt="Hero Image" class="hero-image">
'''

    
    for category, files in categories_data.items():
        if not files:
            continue
        
        html_content += f'<h2>{category}</h2><div class="row">'
        cards_data = []
        for file_path in files:
            try:
                card_data = parse_yaml(file_path)
                if card_data['name'] != 'N/A':  
                    cards_data.append(card_data)
            except Exception as e:
                print(f"Error parsing {file_path}: {e}")

       
        for i, card in enumerate(cards_data):
            first_word = get_first_word(card['namespace'])
            rectangle_color = color_map[first_word]
            file_name = card['name'].lower().replace(' ', '-') + '.html'
            file_path = file_name

            card_html = f'''
                <div class="card-wrapper">
                    <div class="card">
                        <div class="thin-rectangle" style="background-color: {rectangle_color};"></div>
                        <div class="card-body">
                            <div class="namespace">{card['namespace']}</div>
                            <div class="rule-name"><a href="{file_path}">{card['name']}</a></div>
                            <div class="authors">{card['authors']}</div>
                        </div>
                    </div>
                </div>'''

            html_content += card_html

        
        num_cards = len(cards_data)
        num_empty_cells = (4 - (num_cards % 4)) % 4
        if num_empty_cells > 0:
            for _ in range(num_empty_cells):
                html_content += '''
                <div class="card-wrapper">
                    <div class="card" style="visibility: hidden;"></div>
                </div>'''

        html_content += '</div>'

    html_content += '''
    </div>
   
    <script>
        window.addEventListener('DOMContentLoaded', (event) => {
            new PagefindUI({ 
                element: "#search", 
                showSubResults: true,
                showEmptyFilters: false,
                excerptLength: 15,
            });
        });
    </script>
</body>
</html>'''

    with (open(output_html_path, 'w') as output_file):
        output_file.write(html_content)


categories_data = read_file_paths(txt_file_path)


color_map = {}
used_colors = set(predefined_colors)
color_index = 0


all_files = [file for category in categories_data.values() for file in category]
for file_path in all_files:
    try:
        card_data = parse_yaml(file_path)
        first_word = get_first_word(card_data['namespace'])
        if first_word not in color_map:
            if color_index < len(predefined_colors):
                color_map[first_word] = predefined_colors[color_index]
                color_index += 1
            else:
                new_color = generate_color()
                while new_color in used_colors:
                    new_color = generate_color()
                color_map[first_word] = new_color
                used_colors.add(new_color)
    except Exception as e:
        print(f"Error parsing {file_path}: {e}")

generate_html(categories_data, color_map)
print(f'HTML file has been generated: {output_html_path}')
