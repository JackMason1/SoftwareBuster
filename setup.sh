#!/bin/bash

# Get the absolute path of the script
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"

# Create a virtual environment
echo "Creating virtual environment..."
python3 -m venv "$SCRIPT_DIR/ve"

# Activate the virtual environment and install requirements
echo "Installing requirements..."
source "$SCRIPT_DIR/ve/bin/activate"
pip install --upgrade pip
pip install -r "$SCRIPT_DIR/requirements.txt"

# Deactivate the virtual environment
deactivate

# Create the executable script in /usr/local/bin
echo "Creating executable in /usr/local/bin..."
cat << EOF > /usr/local/bin/SoftwareBuster
#!/bin/bash
SCRIPT_DIR="$SCRIPT_DIR"
source "\$SCRIPT_DIR/ve/bin/activate"
python "\$SCRIPT_DIR/SoftwareBuster.py" "\$@"
EOF

# Make the script executable
chmod +x /usr/local/bin/SoftwareBuster

# Create the second executable script in /usr/local/bin
ln -s /usr/local/bin/SoftwareBuster /usr/local/bin/SB

echo "Setup complete! You can now run 'SoftwareBuster' or 'SB' from anywhere."
