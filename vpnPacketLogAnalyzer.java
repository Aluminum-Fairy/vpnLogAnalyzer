import java.io.*;
import java.text.DecimalFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.Scanner;
import java.util.regex.Pattern;
import java.util.stream.Stream;

import logConst.urlConst;

class userList {
	private String name;
	private long count;

	public void addName(String insertName) {
		this.name = insertName;
		this.count = 1;
	}

	public void addCount() {
		this.count++;
	}

	public String getName() {
		return this.name;
	}

	public long getCount() {
		return this.count;
	}
}

class addressList {
	private String address;
	private long count;

	public void addAddress(String insertAddress) {
		this.address = insertAddress;
		this.count = 1;
	}

	public void addCount() {
		this.count++;
	}

	public String getAddress() {
		return this.address;
	}

	public long getCount() {
		return this.count;
	}

	public int getAddrLength() {
		return this.address.length();
	}

	public boolean verifyAddr(String address) {
		return this.address.equals(address);
	}
}

class ipAddressList {
	private byte[] ip = new byte[4];
	private long count;

	public void addAddress(String insertIP) {
		int[] ip = Stream.of(insertIP.split(Pattern.quote("."))).mapToInt(Integer::parseInt).toArray();
		for (int i = 0; i < 4; i++) {
			this.ip[i] = (byte) (ip[i] - 128);
		}
		this.count = 1;
	}

	public void addCount() {
		this.count++;
	}

	public int[] getIp() {
		int ip[] = new int[4];
		for (int i = 0; i < 4; i++) {
			ip[i] = (this.ip[i] + 128) & 0xFF;
		}
		return ip;
	}

	public long getCount() {
		return this.count;
	}

	public boolean verifyIP(String ipAddr) {
		int ipArr[] = this.getIp();
		return ipAddr.equals(ipArr[0] + "." + ipArr[1] + "." + ipArr[2] + "." + ipArr[3]);
	}
}

public class vpnPacketLogAnalyzer {
	public static void main(String[] args) {

		final String version = "1.08.2";

		urlConst urlC = new urlConst();

		String userName, targetUrl, retry = "noInput", fs, httpMethod, searchTimeS, searchTimeE,
				filePath = "/usr/local/vpnserver/packet_log/Main1";
		String packetInfo[] = new String[3];
		File fname;
		int fileLine, httpLine, timeS, timeE, logLine, logTime, maxLength;
		double allFileSize, fileSize;
		boolean bTargetUrl, bUserName, bHttpMethod, bOutput, askSearch;
		ArrayList<String> httplogArr = new ArrayList<String>();
		ArrayList<ArrayList<String>> httplog = new ArrayList<ArrayList<String>>();
		ArrayList<userList> userArr = new ArrayList<userList>();
		ArrayList<addressList> addressArr = new ArrayList<addressList>();
		ArrayList<ipAddressList> ipAddressArr = new ArrayList<ipAddressList>();

		for (int i = 0; i < args.length; i++) {
			if (args[i].contains("filePath=")) {
				filePath = args[i].split("=", 2)[1];
			}
		}

		while (true) {
			cslClear();
			System.out.printf("%5s+-----------------------------------------+\n", "");
			System.out.printf("%5s|   SoftEther VPN Log Analyzer JAVA Ver   |\n", "");
			System.out.printf("%5s+-----------------------------------------+\n", "");
			System.out.printf("%5s%20s %s\n\n", "", "Version", version);

			while (true) {
				File list = new File(filePath);
				File files[] = list.listFiles();
				try {
					Arrays.sort(files);
				} catch (NullPointerException e) {
					System.out.println("ファイルが存在しない、ファイルへのアクセス権限がないなどの理由で読み込み失敗しました。\nプログラムを終了します。");
					System.exit(1);
				}
				allFileSize = 0;
				maxLength = 20;
				for (int i = files.length - 1; i >= 0; i--) {
					if (maxLength < files[i].getName().length()) {
						maxLength = files[i].getName().length();
					}
				}

				for (int i = files.length - 1; i >= 0; i--) {
					fileSize = files[i].length() / 1024.0 / 1024.0;
					allFileSize += fileSize;
					System.out.printf("%3d | %" + maxLength + "s | %3d.%1d MB\n", files.length - i, files[i].getName(),
							(int) fileSize, (int) (fileSize % 1 * 10));
				}
				System.out.printf("\n%5s総ファイル容量: %.2f MB\n\n", "", allFileSize);
				try {
					fname = files[files.length - inputNumData("ファイルを選択(番号)")];
					break;
				} catch (ArrayIndexOutOfBoundsException e) {
					cslClear();
					System.out.println("ファイルのロードに失敗しました\n");
				}
				files = null;
			}
			cslClear();
			System.out.printf("選択されたファイル:%s\n\nロード中...", fname);
			fileLine = 0;
			httpLine = 0;
			String[] logtmp;
			try {
				byte[] data = new byte[(int) fname.length()];
				BufferedInputStream bis = new BufferedInputStream(new FileInputStream(fname));
				bis.read(data);
				bis.close();
				fs = new String(data, "utf-8");
				data = null;
				System.out.print("完了\n  展開中...");
				try {
					String[] fsArr = fs.split("\n", 0);
					for (; fileLine < fsArr.length; fileLine++) {
						if (fsArr[fileLine].contains("HttpUrl")) {
							ArrayList<String> loglinetmp = new ArrayList<String>();
							logtmp = fsArr[fileLine].split(",", 0);
							for (int j = 0; j < logtmp.length; j++) {
								loglinetmp.add(logtmp[j]);
							}
							httpLine++;
							httplog.add((ArrayList<String>) loglinetmp);
						}
					}
					fsArr = null;
				} catch (OutOfMemoryError e) {
					System.out.println("失敗\nメモリ不足です。プログラムを終了します。");
					System.out.println(getMemoryInfo());
					System.exit(1);
				}
			} catch (Exception e) {
				System.out.println("ロードに失敗しました:" + e);
				System.exit(1);
			} catch (OutOfMemoryError e) {
				System.out.print("失敗\nメモリ不足です。低速で読み込みます。\nロード, 展開中...");
				try {
					FileReader filereader = new FileReader(fname);
					BufferedReader fileb = new BufferedReader(filereader);
					String fline;
					try {
						while ((fline = fileb.readLine()) != null) {
							if (fline.contains("HttpUrl")) {
								ArrayList<String> loglinetmp = new ArrayList<String>();
								logtmp = fline.split(",", 0);
								for (int j = 0; j < logtmp.length; j++) {
									loglinetmp.add(logtmp[j]);
								}
								httpLine++;
								httplog.add((ArrayList<String>) loglinetmp);
							}
							fileLine++;
						}
						filereader.close();
					} catch (IOException eee) {
						System.out.println(eee);
					}

				} catch (FileNotFoundException ee) {
					System.out.println("ロードに失敗しました:" + e);
				} catch (OutOfMemoryError ee) {
					System.out.println("失敗\nメモリ不足です。プログラムを終了します。");
					httplog.clear();
					System.out.println(getMemoryInfo());
					System.exit(1);
				}
			}
			fs = null;
			fname = null;
			logtmp = null;

			System.out.print("完了\nユーザーリストを作成しています...");

			boolean userExt;
			for (int i = 0; i < httplog.size(); i++) {
				userExt = false;
				userList userL = new userList();
				userName = httplog.get(i).get(urlC.User).split("-", 0)[1];
				for (int j = 0; j < userArr.size(); j++) {
					if (userArr.get(j).getName().equals(userName)) {
						userArr.get(j).addCount();
						userExt = true;
						break;
					}
				}
				if (!userExt) {
					userL.addName(userName);
					userArr.add(userL);
				}

			}
			userArr.sort(Comparator.comparing(userList::getCount).reversed());

			System.out.print("完了\nアクセスリストを作成しています...");

			boolean addressExt;
			String address;
			for (int i = 0; i < httplog.size(); i++) {
				addressExt = false;
				addressList addrL = new addressList();
				address = httplog.get(i).get(urlC.pakcetInfo).split(" ", 0)[2].split("=", 2)[1].split("://")[1]
						.split("/")[0];
				for (int j = 0; j < addressArr.size(); j++) {
					if (addressArr.get(j).verifyAddr(address)) {
						addressArr.get(j).addCount();
						addressExt = true;
						break;
					}
				}
				if (!addressExt) {
					addrL.addAddress(address);
					addressArr.add(addrL);
				}

			}
			addressArr.sort(Comparator.comparing(addressList::getCount).reversed());
			maxLength = 0;
			for (int i = 0; i < addressArr.size() && i < 10; i++) {
				if (maxLength < addressArr.get(i).getAddrLength()) {
					maxLength = addressArr.get(i).getAddrLength();
				}
			}

			System.out.print("完了\n      IPリストを作成しています...");

			for (int i = 0; i < httplog.size(); i++) {
				addressExt = false;
				ipAddressList ipAddrL = new ipAddressList();
				address = httplog.get(i).get(urlC.accessIP);
				for (int j = 0; j < ipAddressArr.size(); j++) {
					if (ipAddressArr.get(j).verifyIP(address)) {
						ipAddressArr.get(j).addCount();
						addressExt = true;
						break;
					}
				}
				if (!addressExt) {
					ipAddrL.addAddress(address);
					ipAddressArr.add(ipAddrL);
				}

			}
			ipAddressArr.sort(Comparator.comparing(ipAddressList::getCount).reversed());

			System.out.printf("完了\n\n%10s:%8d\n%8s:%8d\n", "ログ行数", fileLine, "検索対象行数", httpLine);

			askSearch = true;
			while (true) {
				System.out.printf("\n%" + maxLength + "s |%8s", "userName", "アクセス数\n");
				for (int i = 0; i < userArr.size(); i++) {
					System.out.printf("%" + maxLength + "s |%8d\n", userArr.get(i).getName(),
							userArr.get(i).getCount());
				}

				System.out.printf("\n%" + maxLength + "s |%8s", "Address", "アクセス数\n");
				for (int i = 0; i < addressArr.size() && i < 10; i++) {
					System.out.printf("%" + -maxLength + "s |%8d\n", addressArr.get(i).getAddress(),
							addressArr.get(i).getCount());
				}

				System.out.printf("\n%" + maxLength + "s |%8s", "IPaddress", "アクセス数\n");
				for (int i = 0; i < ipAddressArr.size() && i < 10; i++) {
					int ipArr[] = ipAddressArr.get(i).getIp();
					System.out.printf("%" + (maxLength - 15) + "d. %3d. %3d. %3d |%8d\n", ipArr[0], ipArr[1], ipArr[2],
							ipArr[3], ipAddressArr.get(i).getCount());
				}

				while (askSearch) {
					retry = inputStrData("\nこのファイルを検索しますか？(y/n)");
					if (retry.equals("y") || retry.equals("n")) {
						break;
					}
				}
				if (askSearch && retry.equals("n")) {
					packetInfo = null;
					userName = null;
					targetUrl = null;
					httpMethod = null;
					retry = null;
					addressArr.clear();
					ipAddressArr.clear();
					userArr.clear();
					httplogArr.clear();
					httplog.clear();
					maxLength = 0;
					break;
				}
				askSearch = false;

				userName = inputStrData("\n検索対象ユーザー名");
				if (userName != "") {
					bUserName = !userName.substring(0, 1).contains("!");
					if (!bUserName) {
						userName = userName.substring(1);
					}
				} else {
					bUserName = true;
				}
				targetUrl = inputStrData("検索対象URL");
				if (targetUrl != "") {
					bTargetUrl = !targetUrl.substring(0, 1).contains("!");
					if (!bTargetUrl) {
						targetUrl = targetUrl.substring(1);
					}
				} else {
					bTargetUrl = true;
				}
				httpMethod = inputStrData("Connection Type");
				if (httpMethod != "") {
					bHttpMethod = !httpMethod.substring(0, 1).contains("!");
					if (!bHttpMethod) {
						httpMethod = httpMethod.substring(1);
					}
				} else {
					bHttpMethod = true;
				}

				while (true) {
					searchTimeS = inputStrData("始点時間(HH:MM)");
					searchTimeE = inputStrData("終点時間(HH:MM)");
					if (searchTimeS != "") {
						timeS = Integer.parseInt(searchTimeS.split(":", 0)[0]) * 60
								+ Integer.parseInt(searchTimeS.split(":", 0)[1]);
					} else {
						timeS = 0;
					}
					if (searchTimeE != "") {
						timeE = Integer.parseInt(searchTimeE.split(":", 0)[0]) * 60
								+ Integer.parseInt(searchTimeE.split(":", 0)[1]);
					} else {
						timeE = 1440;
					}
					if (timeE > timeS) {
						break;
					}
					System.out.println("時間指定をやり直してください");
				}

				while (true) {
					retry = inputStrData("出力しますか(y/n)");
					if (retry.equals("y") || retry.equals("n")) {
						break;
					}
				}
				bOutput = retry.equals("y");

				logLine = 0;
				if (bOutput) {
					System.out.printf("\n\n%9s | %15s | %11s | %s\n", "Time", "userName", "Type", "ConnectionPoint");
				}
				for (int i = 0; i < httplog.size(); i++) {
					httplogArr = httplog.get(i);
					packetInfo = httplogArr.get(urlC.pakcetInfo).split(" ", 0);
					logTime = Integer.parseInt(httplogArr.get(urlC.time).split(":", 0)[0]) * 60
							+ Integer.parseInt(httplogArr.get(urlC.time).split(":", 0)[1]);
					if ((bUserName == httplogArr.get(urlC.User).contains(userName) || userName == "")
							&& (bHttpMethod == packetInfo[1].contains(httpMethod) || httpMethod == "")
							&& (bTargetUrl == packetInfo[2].contains(targetUrl) || targetUrl == "") && timeS <= logTime
							&& timeE >= logTime) {

						if (bOutput) {
							System.out.printf("%9s | %15s | %11s | %s\n",
									httplogArr.get(urlC.time).split(Pattern.quote("."), 0)[0],
									httplogArr.get(urlC.User).split("-", 0)[1], packetInfo[1].split("=", 0)[1],
									packetInfo[2].split("=", 2)[1]);
						}
						logLine++;
					}
				}
				System.out.printf("\n%8d / %8d (%3f %%)\n\n", logLine, httpLine, (float) logLine / httpLine * 100.0);

				while (true) {
					retry = inputStrData("検索条件を指定し直しますか(y/n)");
					if (retry.equals("y") || retry.equals("n")) {
						break;
					}
				}
				if (retry.equals("n")) {
					packetInfo = null;
					userName = null;
					targetUrl = null;
					httpMethod = null;
					retry = "noInput";
					addressArr.clear();
					ipAddressArr.clear();
					userArr.clear();
					httplogArr.clear();
					httplog.clear();
					maxLength = 0;
					break;
				}

			}
		}

	}

	static int inputNumData(String msg) {
		int input;
		Scanner scn = new Scanner(System.in);
		while (true) {
			try {
				System.out.print(msg + ">>");
				input = scn.nextInt();
				break;
			} catch (Exception e) {
				scn.next();
				System.out.println("入力エラー");
			}
		}
		if (input == -2) {
			cslClear();
			System.exit(0);
		} else if (input == -3) {
			System.out.println(getMemoryInfo());
			return inputNumData(msg);
		}
		return input;
	}

	static String inputStrData(String msg) {
		String input;
		Scanner scn = new Scanner(System.in);
		while (true) {
			try {
				System.out.print(msg + ">>");
				input = scn.nextLine();
				break;
			} catch (Exception e) {
				scn.next();
				System.out.println("入力エラー");
			}
		}
		if (input.equals("-2")) {
			cslClear();
			System.exit(0);
		} else if (input.equals("-3")) {
			System.out.println(getMemoryInfo());
			return inputStrData(msg);
		} else if (input.equals("")) {
			return "";
		}
		return input;
	}

	static void cslClear() {
		System.out.print("\033[H\033[2J");
		System.out.flush();
	}

	static String getMemoryInfo() {
		DecimalFormat f1 = new DecimalFormat("#,###KB");
		DecimalFormat f2 = new DecimalFormat("##.#");
		long free = Runtime.getRuntime().freeMemory() / 1024;
		long total = Runtime.getRuntime().totalMemory() / 1024;
		long max = Runtime.getRuntime().maxMemory() / 1024;
		long used = total - free;
		double ratio = (used * 100 / (double) total);
		String info = "Java メモリ情報 : 合計=" + f1.format(total) + "、" + "使用量=" + f1.format(used) + " (" + f2.format(ratio)
				+ "%)、" + "使用可能最大=" + f1.format(max);
		return info;
	}

}
