#!/usr/bin/env python3
"""
SQL Injection Testing Tool Launcher
Educational Use Only
"""

import sys
import os
import subprocess
import importlib.util

def check_python_version():
    """Check if Python version is compatible"""
    if sys.version_info < (3, 7):
        print("❌ Error: Python 3.7 or higher is required")
        print(f"   Current version: {sys.version}")
        print("   Please upgrade Python and try again")
        return False
    print(f"✅ Python version: {sys.version}")
    return True

def check_dependencies():
    """Check if required dependencies are installed"""
    required_packages = {
        'requests': 'requests',
        'urllib3': 'urllib3',
        'tkinter': 'tkinter'
    }

    missing_packages = []

    for package_name, import_name in required_packages.items():
        try:
            if import_name == 'tkinter':
                import tkinter
            else:
                spec = importlib.util.find_spec(import_name)
                if spec is None:
                    missing_packages.append(package_name)
        except ImportError:
            missing_packages.append(package_name)

    if missing_packages:
        print("❌ Missing required packages:")
        for package in missing_packages:
            print(f"   - {package}")
        print("\n📦 To install missing packages, run:")
        print(f"   pip install {' '.join(missing_packages)}")
        print("   or")
        print("   pip install -r requirements.txt")
        return False

    print("✅ All dependencies are installed")
    return True

def check_files():
    """Check if required files exist"""
    required_files = [
        'payload.py',
        'report.py',
        'domain.py',
        'engine.py',
        'user_agent.py'
    ]

    available_tools = []
    missing_files = []

    # Check required files
    for file in required_files:
        if not os.path.exists(file):
            missing_files.append(file)

    if missing_files:
        print("❌ Missing required files:")
        for file in missing_files:
            print(f"   - {file}")
        print("\n⚠️ Warning: Some required components may not work properly.")

    # Check which professional tool is available
    if os.path.exists('sqltool.py'):
        available_tools.append(('🌟 Professional SQL Injection Testing Tool', 'sqltool.py'))

    return available_tools

def show_banner():
    """Display welcome banner"""
    banner = """
    🛡️ SQL INJECTION TESTING TOOL
    ═══════════════════════════════════════════════

    Educational Use Only

    ⚠️  IMPORTANT: This tool is for educational purposes and
    authorized testing only. Never test systems without
    explicit permission.

    🎨 FEATURES:
    • Sleek dark theme with professional styling
    • Single domain and multiple domain support
    • Real-time statistics and progress tracking
    • Advanced payload management (500+ payloads)
    • Professional reporting capabilities
    • Syntax highlighting and visual feedback
    • 200+ modern user agents for stealth
    • Database fingerprinting and detection

    """
    print(banner)

def select_tool(available_tools):
    """Let user select which tool to run"""
    if len(available_tools) == 0:
        print("❌ No tools available to launch.")
        return None
    
    if len(available_tools) == 1:
        print(f"🚀 Launching: {available_tools[0][0]}")
        return available_tools[0][1]

    print("📋 Available tools:")
    for i, (name, file) in enumerate(available_tools, 1):
        print(f"   {i}. {name}")

    while True:
        try:
            choice = input(f"\n🎯 Select tool to launch (1-{len(available_tools)}): ").strip()
            index = int(choice) - 1
            if 0 <= index < len(available_tools):
                return available_tools[index][1]
            else:
                print("❌ Invalid choice. Please try again.")
        except (ValueError, KeyboardInterrupt):
            print("\n❌ Invalid input or cancelled by user.")
            return None

def launch_tool(tool_file):
    """Launch the selected tool"""
    try:
        print(f"\n🚀 Launching {tool_file}...")
        print("   Close the application window to return to this launcher.\n")

        # Get module name from file name (without .py extension)
        module_name = os.path.splitext(tool_file)[0]

        # Use importlib to dynamically import the module
        spec = importlib.util.spec_from_file_location(module_name, tool_file)
        if spec is None:
            print(f"❌ Could not find {tool_file}")
            return False

        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)

        # Check if main function exists
        if not hasattr(module, 'main'):
            print(f"❌ The 'main' function was not found in {tool_file}")
            return False

        # Launch the tool
        module.main()
        return True

    except ImportError as e:
        print(f"❌ Import error with {tool_file}: {e}")
        return False
    except Exception as e:
        print(f"❌ Error running {tool_file}: {e}")
        return False

def install_dependencies():
    """Try to install dependencies automatically"""
    print("🔧 Attempting to install dependencies...")
    required_packages = ['requests', 'urllib3']

    try:
        for package in required_packages:
            subprocess.check_call([sys.executable, '-m', 'pip', 'install', package])
        print("✅ Dependencies installed successfully!")
        return True
    except Exception as e:
        print(f"❌ Failed to install dependencies: {e}")
        print("   Please install them manually:")
        print(f"   pip install {' '.join(required_packages)}")
        return False

def main():
    """Main launcher function"""
    show_banner()

    # Check Python version
    if not check_python_version():
        input("Press Enter to exit...")
        return

    # Check dependencies
    if not check_dependencies():
        choice = input("\n📦 Would you like to try installing dependencies automatically? (y/n): ").lower()
        if choice in ['y', 'yes']:
            if not install_dependencies():
                input("Press Enter to exit...")
                return
            # Re-check dependencies after installation
            if not check_dependencies():
                input("Press Enter to exit...")
                return
        else:
            input("Press Enter to exit...")
            return

    # Check files
    available_tools = check_files()

    if not available_tools:
        print("\n⚠️ No tools available to launch.")
        print("   Please make sure the main tool file exists:")
        print("   • sqltool.py")
        input("Press Enter to exit...")
        return

    print(f"✅ Found {len(available_tools)} tool(s)")

    # Select and launch tool
    while True:
        selected_tool = select_tool(available_tools)
        if not selected_tool:
            break

        if launch_tool(selected_tool):
            print("\n✅ Tool closed successfully.")
        else:
            print("\n❌ Tool failed to launch.")

        # Ask if user wants to launch the tool again
        choice = input("\n🔄 Would you like to launch the tool again? (y/n): ").lower()
        if choice not in ['y', 'yes']:
            break

    print("\n👋 Thanks for using the Professional SQL Injection Testing Tool!")
    print("   Remember to use it responsibly and ethically.")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n👋 Goodbye!")
    except Exception as e:
        print(f"\n❌ Unexpected error: {e}")
        input("Press Enter to exit...")
