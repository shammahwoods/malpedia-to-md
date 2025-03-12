# Malpedia Markdown Converter
This script imports malware family data from Malpedia's API into Markdown files for use in Obsidian or other knowledge management systems. It works alongside and is based on Christian Taillon's [APT Tracker Markdown Converter](https://github.com/christian-taillon/apt-tracker-md) to create a threat intelligence knowledge base with consistent attribution between threat actors and malware families.
## Features
- Fetches malware family information from Malpedia's API
- Creates structured Markdown files organized by platform
- Resolves attribution links to use consistent group names
- Maps alternative group names to their primary names
## Prerequisites
1. Python 3.6+
2. Access to Malpedia API (It is free and unauthenticated)
3. APT Groups and Operations data from https://apt.threattracking.com/ (Download as xlsx)
## Setup
1. Clone this repository:
    `git clone https://github.com/yourusername/malpedia-importer.git cd malpedia-importer`
2. Create a virtual environment:
    `python -m venv venv source venv/bin/activate (Linux)`
3. Install the required packages:
    `pip install requests openpyxl`
## Usage
1. Run the script:
    `python malpedia-to-md.py`
2. The script will:
    - Create a `Malware` directory with subdirectories for each platform
    - Generate Markdown files for each malware family
    - Map attribution to consistent group names
    - Display progress during the import process
    - **This process will take around 100 minutes to respect Malpedia's rate limit**
## How It Works
The script follows these steps:
1. Builds a map of existing malware family files to avoid duplicate processing
2. Creates a mapping of alternative group names to their primary names from the APT data
3. Fetches the list of all malware families from Malpedia
4. For each malware family not already indexed:
    - Fetches detailed information from the API
    - Resolves attribution to use consistent group names
    - Creates a properly formatted Markdown file
## Output Structure
Each malware family is saved in its own Markdown file with:
- YAML frontmatter with metadata
- Attribution links to primary actor names
- Main heading
- Alternative names
- Description
- References
Markdown files are organized into directories by platform (Windows, Linux, etc.).
