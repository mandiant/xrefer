# XRefer: The Binary Navigator

<p align="center">
  <img src="images/xrefer_logo_main.png" alt="XRefer Logo" width="400">
</p>


XRefer is a Python-based plugin for the [IDA Pro disassembler](https://hex-rays.com/ida-pro), a tool used for analyzing software. The plugin provides a custom navigation interface within IDA. It examines execution paths from entry points, breaks down the binary into clusters of related functions, and highlights downstream behaviors and artifacts for quicker insights. XRefer can incorporate external data (e.g., API traces, capa results, user-defined xrefs) and provides path graphs for richer context. It integrates with Google's Gemini model to produce natural language descriptions of code relationships and behaviors. Additionally, XRefer can provide cluster based labels for functions, aiming to accelerate the manual static analysis process.

More can be read about XRefer in the accompanying [blog post](https://cloud.google.com/blog/topics/threat-intelligence/xrefer-gemini-assisted-binary-navigator).

## Installation

1. **Clone the Repository:**
  ```
  git clone https://github.com/mandiant/xrefer.git
  ```

2. **Install the Plugin:**
- Inside the cloned repository, a `plugins` directory contains the plugin code.
- Copy the contents of `plugins/` into your IDA Pro `plugins` directory:
```
cp -r xrefer/plugins/* /path/to/IDA/plugins/
```

3. **Install Dependencies:**
From the main directory of the cloned repository:
  ```
  pip install -r requirements.txt
  ```

_Note: The `asciinet` dependency requires Java to be installed. OpenJDK or any JRE should work. Ensure `java` is accessible on your system's PATH._

## Usage

After installation, restart IDA. You will find XRefer's menu entries under `Edit -> XRefer`. Some options will also be available under the right click context menu.

- **Configuration:**  
Go to `Edit -> XRefer -> Configure` to adjust LLM settings, paths, exclusions and other settings.

- **Starting Analysis:**  
Run analysis either from the default entry point `Edit -> XRefer -> Run Analysis -> Default Entrypoint` or specify a custom entry point `Edit -> XRefer -> Run Analysis -> Custom Entrypoint` in the case of a DLL/library for example.

- **External Data & Exclusions:**  
XRefer can ingest external data sources, including API trace files from dynamic analysis sandboxes VMRay and Cape. It can also ingest capa analysis outputs, and user-defined indirect xrefs for enhanced path resolution. These inputs help enrich the analysis with additional context. Manage default paths for these resources from the configuration dialog and fine-tune their usage by enabling or disabling exclusions, as well as adding or removing exclusion entries to focus on the most relevant artifacts.

For more in-depth instructions and usage scenarios, please refer to the [Usage Documentation](docs/usage.md).

![x](/images/navigation.gif)

## Contributing

Contributions, bug reports, and feature requests are welcome. Please open an issue or submit a pull request with a clear description of the proposed changes.

## Important Privacy Notice

XRefer's LLM-based features, when enabled, send portions of analyzed data (e.g., APIs, strings, library references, and function relationships) to external servers, such as Google's Gemini API or other configured LLM endpoints. These external services process the information to generate natural language descriptions and insights. If you are analyzing sensitive binaries or prefer not to share data outside your local environment, you can disable all LLM features in the settings, preventing any external communication. Please consult Google Gemini's [Terms of Service](https://cloud.google.com/gemini/docs/discover/data-governance)  before use.
