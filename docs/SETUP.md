# ⚙️ Setup Guide

To use Folder-Stream like a command from **any** folder on your computer, follow these steps.

### 1. Copy the Path
Copy the full path to your `Folder-Stream` directory.
Example: `C:\Apps\Folder-Stream`

### 2. Open Environment Variables
1. Press `Win + S` and type **"env"**.
2. Select **"Edit the system environment variables"**.
3. Click **"Environment Variables"** at the bottom.

### 3. Edit System Path
1. Under **"System variables"**, find the row named **Path** and double-click it.
2. Click **"New"** and paste your folder path.
   ```text
   E:\InstalledApplications\AppTools\Folder-Stream
   ```
3. Click **OK** on all windows.

### 4. Use it Everywhere
Now, open any folder in your terminal and type:
```bash
serve
```
The server will instantly start serving that specific folder.
