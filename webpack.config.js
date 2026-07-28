/********************************************************************************
 * Copyright (C) 2026 CoCreate and Contributors.
 *
 * Licensed under GNU AGPLv3.
 ********************************************************************************/

import path from "node:path";
import { fileURLToPath } from "node:url";
import webpack from "webpack";
import { EsbuildPlugin } from "esbuild-loader";
import { transformSync } from "esbuild";
import { FileUploader } from "@cocreate/webpack";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

/**
 * Webpack plugin that converts compiled code into an inline JSON string payload
 * wrapped inside a self-executing bootstrapper construct. Extracts the file on app startup
 * and nullifies its own reference to trigger immediate V8 garbage collection.
 */
class SelfCleaningBundlePlugin {
    constructor(options = {}) {
        this.isProduction = options.isProduction ?? false;
    }

    apply(compiler) {
        compiler.hooks.compilation.tap("SelfCleaningBundlePlugin", (compilation) => {
            compilation.hooks.processAssets.tap(
                {
                    name: "SelfCleaningBundlePlugin",
                    stage: webpack.Compilation.PROCESS_ASSETS_STAGE_OPTIMIZE_TRANSFER
                },
                (assets) => {
                    for (const assetName of Object.keys(assets)) {
                        if (assetName.endsWith(".js")) {
                            const rawSourceCode = assets[assetName].source().toString();
                            
                            // JSON.stringify handles escaping and is ~30% smaller on disk than Base64
                            const jsonEscapedPayload = JSON.stringify(rawSourceCode);

                            let wrappedCode = `/********************************************************************************
 * Copyright (C) 2026 CoCreate and Contributors.
 *
 * Licensed under GNU AGPLv3.
 ********************************************************************************/

import fs from "node:fs";
import path from "node:path";

/**
 * Self-Executing & Self-Cleaning ACME Plugin Bootstrapper Construct
 * Encapsulates JSON payload string and releases V8 heap memory immediately upon execution.
 */
let bootstrapperContainer = {
    payload: ${jsonEscapedPayload},

    extractDatabase() {
        try {
            const storageDir = path.join(process.cwd(), ".plugins");
            const dbPath = path.join(storageDir, "acme.js");

            // 1. Ensure .plugins directory exists
            if (!fs.existsSync(storageDir)) {
                fs.mkdirSync(storageDir, { recursive: true });
            }

            // 2. Extract embedded payload to disk if missing
            if (!fs.existsSync(dbPath)) {
                if (this.payload) {
                    console.log("[Storage Boot] Extracting embedded ACME payload to: " + dbPath);
                    
                    // Direct UTF-8 write without binary decoding overhead
                    fs.writeFileSync(dbPath, this.payload, "utf8");
                    console.log("[Storage Boot] ACME payload extraction complete.");
                } else {
                    console.log("[Storage Boot] ACME module missing, but no embedded payload present.");
                }
            } else {
                console.log("[Storage Boot] ACME module present on disk at: " + dbPath);
            }
        } catch (err) {
            console.error("[Storage Boot Error] Failed to extract ACME payload:", err.message);
        } finally {
            // 3. Dereference payload string to allow V8 memory reclaim
            this.payload = null;
        }
    }
};

// 4. Synchronously execute extraction on application launch
if (bootstrapperContainer) {
    bootstrapperContainer.extractDatabase();
    // 5. Dereference container variable for V8 GC reclamation
    bootstrapperContainer = null;
}
`;

                            if (this.isProduction) {
                                const minifiedResult = transformSync(wrappedCode, {
                                    loader: "js",
                                    target: "node18",
                                    minify: true,
                                    legalComments: "inline"
                                });
                                wrappedCode = minifiedResult.code;
                            }

                            compilation.updateAsset(
                                assetName,
                                new webpack.sources.RawSource(wrappedCode)
                            );
                        }
                    }
                }
            );
        });
    }
}

export default async (env, argv) => {
    const isProduction = argv && argv.mode === "production";

    // Base configuration shared across distribution and installer targets
    const baseConfig = {
        target: "node",
        experiments: {
            outputModule: true
        },
        resolve: {
            extensions: [".js", ".mjs", ".cjs", ".json", ".ts"],
            fullySpecified: false
        },
        node: {
            __dirname: false,
            __filename: false
        },
        devtool: false,

        module: {
            exprContextCritical: false,
            unknownContextCritical: false,
            rules: [
                {
                    test: /\.m?[jc]s$/,
                    type: "javascript/auto",
                    resolve: {
                        fullySpecified: false
                    }
                },
                {
                    test: /\.js$/,
                    exclude: /node_modules/,
                    use: {
                        loader: "esbuild-loader",
                        options: {
                            loader: "js",
                            target: "node18"
                        }
                    }
                },
                {
                    test: /\.ts$/,
                    exclude: [/node_modules/, /\.d\.ts$/],
                    use: {
                        loader: "esbuild-loader",
                        options: {
                            loader: "ts",
                            target: "node18"
                        }
                    }
                }
            ]
        },
        performance: {
            hints: false
        }
    };

    const commonPlugins = [
        new webpack.optimize.LimitChunkCountPlugin({
            maxChunks: 1
        }),
        // Ignore optional dependencies, encoding, native WebSocket packages, and type definitions
        new webpack.IgnorePlugin({
            resourceRegExp: /^(cardinal|gcp-metadata|aws-sdk|bufferutil|utf-8-validate|encoding|\.d\.ts)$/
        })
    ];

    const distributionConfig = {
        ...baseConfig,
        name: "distribution",
        mode: isProduction ? "production" : "development",
        entry: "./src/index.js",
        output: {
            path: path.resolve(__dirname, "dist"),
            filename: "acme.js",
            library: {
                type: "module"
            },
            clean: true,
            globalObject: "this"
        },
        optimization: {
            minimize: isProduction,
            minimizer: [
                new EsbuildPlugin({
                    target: "node18"
                })
            ],
            splitChunks: false,
            runtimeChunk: false
        },
        plugins: [
            ...commonPlugins,
            new FileUploader(env, argv)
        ]
    };

    const installerConfig = {
        ...baseConfig,
        name: "installer",
        mode: isProduction ? "production" : "development",
        entry: "./src/index.js",
        output: {
            path: path.resolve(__dirname, "installer"),
            filename: "acme.installer.js",
            library: {
                type: "module"
            },
            clean: true,
            globalObject: "this"
        },
        optimization: {
            minimize: isProduction,
            minimizer: [
                new EsbuildPlugin({
                    target: "node18"
                })
            ],
            splitChunks: false,
            runtimeChunk: false
        },
        plugins: [
            ...commonPlugins,
            new SelfCleaningBundlePlugin({ isProduction })
        ]
    };

    return [distributionConfig, installerConfig];
};