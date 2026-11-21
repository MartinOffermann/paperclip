import { QUALIFIED_OPENCODE_VERSION } from "../drivers/opencode/opencode-server-driver.js";
import {
  chmodSync,
  closeSync,
  fstatSync,
  fsyncSync,
  lstatSync,
  mkdirSync,
  openSync,
  readlinkSync,
  readSync,
  rmdirSync,
  symlinkSync,
  unlinkSync,
  writeSync,
} from "node:fs";
import { basename, dirname, isAbsolute, join } from "node:path";

export const TRUSTED_OPENCODE_EXECUTABLE_ARG =
  "--paperclip-trusted-opencode-executable";

const unavailableBinding = (reason: string) => new Error(
  `OpenCode ${QUALIFIED_OPENCODE_VERSION} runner-owned executable binding is unavailable (${reason}); refusing ambient PATH or PAPERCLIP_OPENCODE_COMMAND fallback`,
);
const permissionBits = (mode: number | bigint) =>
  Number(typeof mode === "bigint" ? mode & 0o777n : mode & 0o777);

export function withoutAmbientOpenCodeCommand(
  environment: NodeJS.ProcessEnv,
): NodeJS.ProcessEnv {
  const sanitized = { ...environment };
  delete sanitized.PAPERCLIP_OPENCODE_COMMAND;
  return sanitized;
}

/**
 * Consumes only the binding injected by runnerd after its startup profile has
 * authenticated the executable. An inherited descriptor keeps the verified
 * file identity bound through the nested Node spawn on supported Unix hosts;
 * unsupported platforms fail closed in runnerd before this proxy starts.
 */
export function trustedOpenCodeLaunchBinding(
  args: readonly string[],
): {
  command: string;
  commandFd?: number;
  commandLifecycle?: {
    beforeSpawn(): void;
    afterSpawn(): void;
    afterExit(): void;
  };
} {
  const command = args.length === 2 && args[0] === TRUSTED_OPENCODE_EXECUTABLE_ARG
    ? args[1]!
    : "";
  const matched = process.platform === "linux"
    ? command.match(/^\/proc\/self\/fd\/(\d+)$/)
    : null;
  const commandFd = Number(matched?.[1]);
  if (matched && Number.isInteger(commandFd) && commandFd >= 3 && commandFd <= 255) {
    return { command, commandFd };
  }
  const privateRoot = dirname(dirname(command));
  const binDirectory = dirname(command);
  let loaderLinkTarget: string | undefined;
  const validateMacSnapshot = (expected?: { dev: number; ino: number }) => {
    let snapshotIsValid = false;
    let metadata: ReturnType<typeof lstatSync> | undefined;
    try {
      metadata = lstatSync(command);
      const binMetadata = lstatSync(binDirectory);
      const rootMetadata = lstatSync(privateRoot);
      let loaderLinkIsValid = loaderLinkTarget === undefined;
      try {
        const loaderMetadata = lstatSync(join(privateRoot, "lib"));
        loaderLinkIsValid = loaderLinkTarget !== undefined &&
          loaderMetadata.isSymbolicLink() &&
          readlinkSync(join(privateRoot, "lib")) === loaderLinkTarget;
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
      }
      const currentUid = process.getuid?.();
      snapshotIsValid =
        metadata.isFile() &&
        !metadata.isSymbolicLink() &&
        metadata.nlink === 1 &&
        (metadata.mode & 0o777) === 0o500 &&
        binMetadata.isDirectory() &&
        !binMetadata.isSymbolicLink() &&
        (binMetadata.mode & 0o777) === 0o700 &&
        rootMetadata.isDirectory() &&
        !rootMetadata.isSymbolicLink() &&
        (rootMetadata.mode & 0o777) === 0o700 &&
        loaderLinkIsValid &&
        currentUid !== undefined &&
        metadata.uid === currentUid &&
        binMetadata.uid === currentUid &&
        rootMetadata.uid === currentUid &&
        (expected === undefined ||
          (metadata.dev === expected.dev && metadata.ino === expected.ino));
    } catch {
      snapshotIsValid = false;
    }
    if (!snapshotIsValid) {
      // Stable predicate names only: paths, ownership values, inode values,
      // symlink targets, and raw filesystem errors can contain sensitive data.
      const reasons: string[] = [];
      if (!metadata) reasons.push("executable_metadata_unavailable");
      else {
        if (!metadata.isFile()) reasons.push("executable_not_regular_file");
        if (metadata.isSymbolicLink()) reasons.push("executable_is_symlink");
        if (metadata.nlink !== 1) reasons.push("executable_link_count");
        if (permissionBits(metadata.mode) !== 0o500) reasons.push("executable_mode");
      }
      try {
        const bin = lstatSync(binDirectory);
        if (!bin.isDirectory()) reasons.push("bin_not_directory");
        if (bin.isSymbolicLink()) reasons.push("bin_is_symlink");
        if (permissionBits(bin.mode) !== 0o700) reasons.push("bin_mode");
        if (bin.uid !== process.getuid?.()) reasons.push("bin_owner");
      } catch { reasons.push("bin_metadata_unavailable"); }
      try {
        const root = lstatSync(privateRoot);
        if (!root.isDirectory()) reasons.push("private_root_not_directory");
        if (root.isSymbolicLink()) reasons.push("private_root_is_symlink");
        if (permissionBits(root.mode) !== 0o700) reasons.push("private_root_mode");
        if (root.uid !== process.getuid?.()) reasons.push("private_root_owner");
      } catch { reasons.push("private_root_metadata_unavailable"); }
      try {
        const linkPath = join(privateRoot, "lib");
        const link = lstatSync(linkPath);
        if (
          loaderLinkTarget === undefined || !link.isSymbolicLink() ||
          readlinkSync(linkPath) !== loaderLinkTarget
        ) reasons.push("loader_link");
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code !== "ENOENT" || loaderLinkTarget !== undefined) {
          reasons.push("loader_link");
        }
      }
      const currentUid = process.getuid?.();
      if (currentUid === undefined) reasons.push("effective_uid_unavailable");
      else if (metadata && metadata.uid !== currentUid) reasons.push("executable_owner");
      if (expected && metadata && (metadata.dev !== expected.dev || metadata.ino !== expected.ino)) {
        reasons.push("executable_identity");
      }
      throw unavailableBinding(reasons.join(",") || "snapshot_validation");
    }
    return metadata!;
  };
  const macPathFailures = [
    [isAbsolute(command), "executable_path_not_absolute"],
    [command === join(privateRoot, "bin", "launch"), "executable_path_structure"],
    [basename(command) === "launch", "executable_name"],
    [basename(binDirectory) === "bin", "bin_directory_name"],
    [/^\.?paperclip-verified-executable-[0-9a-f]{32}$/.test(basename(privateRoot)), "private_root_name"],
  ] as const;
  if (
    process.platform === "darwin" &&
    macPathFailures.every(([valid]) => valid)
  ) {
    try {
      const loaderMetadata = lstatSync(join(privateRoot, "lib"));
      if (!loaderMetadata.isSymbolicLink()) throw new Error("verified OpenCode loader link changed");
      loaderLinkTarget = readlinkSync(join(privateRoot, "lib"));
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
    }
    const initialMetadata = validateMacSnapshot();
    let sourceFd: number;
    try {
      sourceFd = openSync(command, "r");
    } catch {
      throw unavailableBinding("executable_open_failed");
    }
    const sourceMetadata = fstatSync(sourceFd);
    if (
      sourceMetadata.dev !== initialMetadata.dev ||
      sourceMetadata.ino !== initialMetadata.ino
    ) {
      closeSync(sourceFd);
      throw unavailableBinding("executable_identity");
    }
    try {
      unlinkSync(command);
    } catch (error) {
      closeSync(sourceFd);
      throw error;
    }
    let materialized = false;
    let materializedIdentity: { dev: number; ino: number } | undefined;
    const materializeForSpawn = () => {
      if (materialized) {
        throw new Error("Verified OpenCode executable is still in use");
      }
      let destinationFd: number | undefined;
      let destinationIdentity: { dev: number; ino: number } | undefined;
      try {
        try {
          mkdirSync(privateRoot, { mode: 0o700 });
        } catch (error) {
          if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error;
        }
        const rootMetadata = lstatSync(privateRoot);
        if (
          !rootMetadata.isDirectory() || rootMetadata.isSymbolicLink() ||
          (rootMetadata.mode & 0o777) !== 0o700 || rootMetadata.uid !== process.getuid?.()
        ) throw new Error("verified OpenCode private root changed");
        if (loaderLinkTarget) {
          try {
            symlinkSync(loaderLinkTarget, join(privateRoot, "lib"));
          } catch (error) {
            if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error;
          }
        }
        try {
          mkdirSync(binDirectory, { mode: 0o700 });
        } catch (error) {
          if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error;
        }
        const binMetadata = lstatSync(binDirectory);
        if (
          !binMetadata.isDirectory() || binMetadata.isSymbolicLink() ||
          (binMetadata.mode & 0o777) !== 0o700 || binMetadata.uid !== process.getuid?.()
        ) throw new Error("verified OpenCode bin directory changed");
        destinationFd = openSync(command, "wx", 0o700);
        const created = fstatSync(destinationFd);
        destinationIdentity = { dev: created.dev, ino: created.ino };
        const buffer = Buffer.allocUnsafe(64 * 1024);
        let sourceOffset = 0;
        while (sourceOffset < sourceMetadata.size) {
          const count = readSync(
            sourceFd,
            buffer,
            0,
            Math.min(buffer.length, sourceMetadata.size - sourceOffset),
            sourceOffset,
          );
          if (count === 0) throw new Error("verified OpenCode snapshot ended early");
          let written = 0;
          while (written < count) {
            const writeCount = writeSync(
              destinationFd,
              buffer,
              written,
              count - written,
            );
            if (writeCount === 0) {
              throw new Error("verified OpenCode snapshot copy made no progress");
            }
            written += writeCount;
          }
          sourceOffset += count;
        }
        fsyncSync(destinationFd);
        chmodSync(command, 0o500);
        materializedIdentity = destinationIdentity;
        closeSync(destinationFd);
        destinationFd = undefined;
        materialized = true;
        validateMacSnapshot(materializedIdentity);
      } catch (error) {
        if (destinationFd !== undefined) closeSync(destinationFd);
        try {
          if (destinationIdentity) {
            const current = lstatSync(command);
            if (
              current.isFile() && !current.isSymbolicLink() && current.nlink === 1 &&
              current.dev === destinationIdentity.dev && current.ino === destinationIdentity.ino
            ) unlinkSync(command);
          }
        } catch {
          // Preserve unexpected or substituted directory entries.
        }
        try {
          rmdirSync(binDirectory);
        } catch {
          // Preserve the original materialization failure.
        }
        throw error;
      }
    };
    return {
      command,
      commandLifecycle: {
        // Descriptor execution is unavailable on macOS. Same-UID filesystem
        // attackers are outside the documented local-host trust boundary in
        // docs/durable-recovery.md. Keep the verified source on an unlinked
        // descriptor, rematerialize only at the syscall boundary (including
        // retries). Keep its private pathname until the child exits: deleting
        // a signed executable during macOS startup can kill or stall the child.
        beforeSpawn: materializeForSpawn,
        afterSpawn() {
          validateMacSnapshot(materializedIdentity);
        },
        afterExit() {
          if (!materialized) return;
          validateMacSnapshot(materializedIdentity);
          unlinkSync(command);
          rmdirSync(binDirectory);
          const loaderLink = join(privateRoot, "lib");
          try {
            const loaderMetadata = lstatSync(loaderLink);
            if (
              loaderLinkTarget !== undefined && loaderMetadata.isSymbolicLink() &&
              readlinkSync(loaderLink) === loaderLinkTarget
            ) unlinkSync(loaderLink);
          } catch (error) {
            if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
          }
          rmdirSync(privateRoot);
          materialized = false;
          materializedIdentity = undefined;
        },
      },
    };
  }
  const reason = args.length !== 2 || args[0] !== TRUSTED_OPENCODE_EXECUTABLE_ARG
    ? "binding_arguments"
    : process.platform !== "darwin" && process.platform !== "linux"
      ? "unsupported_platform"
      : process.platform === "darwin"
        ? macPathFailures.find(([valid]) => !valid)?.[1] ?? "macos_path_shape"
        : "linux_descriptor_shape";
  throw unavailableBinding(reason);
}
