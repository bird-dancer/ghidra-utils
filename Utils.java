package Utils; // TODO: Change package name

import java.nio.charset.StandardCharsets;
import java.util.Arrays;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.util.task.TaskMonitor;

public class Utils {
	public static long find_string_offset(ByteProvider provider, long start, long end, String target)
			throws Exception {
		byte[] candidate;
		BinaryReader reader = new BinaryReader(provider, true);
		byte[] targetBytes = target.getBytes(StandardCharsets.UTF_8);
		long lastPossibleAddr = end - targetBytes.length;

		for (long offset = start; offset <= lastPossibleAddr; offset++) {
			reader.setPointerIndex(offset);
			candidate = reader.readNextByteArray(targetBytes.length);

			if (Arrays.equals(candidate, targetBytes)) {
				System.out.printf("found string \"%s\" at offset: 0x%X\n", target, offset);
				return offset;
			}
		}
		throw new Exception("String: " + target + " not found");
	}

	private static void copy_mem_block(String name, long source, long dest, long size, boolean init,
			boolean exe,
			boolean read,
			boolean write, TaskMonitor monitor, ByteProvider provider, Program program)
			throws Exception {
		if (size == 0)
			return;

		MemoryBlock data;
		Memory mem = program.getMemory();
		Address dest_addr = program.getAddressFactory().getDefaultAddressSpace()
				.getAddress(dest);

		if (!init)
			data = mem.createUninitializedBlock(name, dest_addr, size, false);
		else if (source >= 0)
			data = mem.createInitializedBlock(name, dest_addr, size,
					(byte) 0,
					monitor, false);
		else
			throw new Exception("should be initialized but invalid source address provided: " + source);

		data.setExecute(exe);
		data.setRead(read);
		data.setWrite(write);

		byte data_bytes[] = provider.readBytes(source, size);
		mem.setBytes(dest_addr, data_bytes);
	}

	public static void copy_mem_block(String name, long source, long dest, long size, boolean exe,
			boolean read,
			boolean write, TaskMonitor monitor, ByteProvider provider, Program program)
			throws Exception {
		if (source < 0)
			throw new Exception("invalid source address");

		copy_mem_block(name, source, dest, size, true, exe, read, write, monitor, provider, program);

	}

	public static void create_mem_block(String name, long dest, long size, boolean exe,
			boolean read,
			boolean write, TaskMonitor monitor, ByteProvider provider, Program program)
			throws Exception {
		copy_mem_block(name, -1, dest, size, false, exe, read, write, monitor, provider, program);
	}
}
