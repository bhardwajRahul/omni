# zstd-dict

zstd-dict is a tool for generating a zstd dictionary used to compress resources containing partial or full Talos machine configurations, such as `ClusterMachineConfig` and `ConfigPatch`.

The dictionary is generated using a training set consisting of:

- Randomly generated Talos machine configuration YAMLs
- ArgoCD application manifests generated via the `helm template` command

Kubernetes manifests are included because they are commonly used in the `inlineManifests` section of Talos machine configurations.

This tool updates the `client/pkg/compression/data/config.zdict` dictionary file under the Omni project root. It also writes the input files used for training into the `inputs/` directory.

The `inputs/` directory can then be used as input to generate a dictionary using the `zstd` command-line tool.

To generate a dictionary via command line:

1. Install `zstd`
2. In the directory of this tool, run the following command:

```bash
export DICT_ID=1
zstd --train -r inputs -o ../../client/pkg/compression/data/config.$DICT_ID.zdict --dictID $DICT_ID --maxdict=64KB
```

**Note:** The dictionary trained via command line might produce different, potentially better results than the one generated by this tool. Compare the results of both dictionaries before deciding
which one to use.

**Note:** When updating the dictionary, follow these steps to maintain backward compatibility:

1. Increment the dictionary ID in this tool.
2. Update the shell command above with the new dictionary ID.
3. In the `client/pkg/compression/data/` package, add the new dictionary file without removing the old ones.
4. Update the code in the compression package to handle multiple dictionary versions, ensuring that the decoder can still access and use the old dictionaries when needed.

These steps are crucial to maintain compatibility with data compressed using previous dictionary versions.