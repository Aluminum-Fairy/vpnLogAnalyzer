import java.io.*;
import java.text.DecimalFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Scanner;
import java.util.regex.Pattern;

import logConst.urlConst;

public class vpnPacketLogAnalyzerBeta {
	public static void main(String[] args) {

		urlConst urlC = new urlConst();

		String UserName, targetUrl, retry, fs, httpMethod, sTime, eTime, filePath = "./PacketLog/";
		String packetInfo[] = new String[3];
		File fname;
		int lineNum, httpLineNum, minS, minE, printLineNum, logTime;
		double fileSize = 0;
		boolean bTargetUrl, bUserName, bHttpMethod, bOutput;
		final String version = "1.07.0(b00)";
		ArrayList<String> httplogArr = new ArrayList<String>();
		ArrayList<ArrayList<String>> httplog = new ArrayList<ArrayList<String>>();

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
				fileSize = 0;
				for (int i = files.length - 1; i >= 0; i--) {
					fileSize += files[i].length() / 1024.0 / 1024.0;
					System.out.printf("%3d | %30s | %.3fMB\n", files.length - i, files[i],
							files[i].length() / 1024.0 / 1024.0);
				}
				System.out.printf("\n%5s総ファイル容量: %.2f MB\n\n", "",fileSize);
				try {
					fname = files[files.length - inputNumData("ファイルを選択(番号)")];
					break;
				} catch (ArrayIndexOutOfBoundsException e) {
					cslClear();
					System.out.println("ファイルのロードに失敗しました");
				}
				files = null;
			}
			cslClear();
			System.out.printf("選択されたファイル:%s\nロード中...", fname);
			lineNum = 0;
			httpLineNum = 0;
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
					for (; lineNum < fsArr.length; lineNum++) {
						if (fsArr[lineNum].contains("HttpUrl")) {
							ArrayList<String> loglinetmp = new ArrayList<String>();
							logtmp = fsArr[lineNum].split(",", 0);
							for (int j = 0; j < logtmp.length; j++) {
								loglinetmp.add(logtmp[j]);
							}
							httpLineNum++;
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
				fs = "";
				System.exit(1);
			} catch (OutOfMemoryError e) {
				System.out.print("失敗\nメモリ不足です。低速で読み込みます。\nロード, 展開中...");
				fs = "";
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
								httpLineNum++;
								httplog.add((ArrayList<String>) loglinetmp);
							}
							lineNum++;
						}
						filereader.close();
					} catch (IOException eee) {
						System.out.println(eee);
					}

				} catch (FileNotFoundException ee) {
					System.out.println("ロードに失敗しました:" + e);
				} catch (OutOfMemoryError ee) {
					System.out.println("失敗\nメモリ不足です。プログラムを終了します。");
					System.out.println(getMemoryInfo());
					System.exit(1);
				}
			}
			fs = null;
			fname = null;
			logtmp = null;

			System.out.printf("完了\n%10s:%8d\n%8s:%8d\n", "ログ行数", lineNum, "検索対象行数", httpLineNum);

			while (true) {
				UserName = inputStrData("\n検索対象ユーザー名");
				if (UserName != "") {
					bUserName = !UserName.substring(0, 1).contains("!");
					if (!bUserName) {
						UserName = UserName.substring(1);
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
					sTime = inputStrData("始点時間(HH:MM)");
					eTime = inputStrData("終点時間(HH:MM)");
					if (sTime != "") {
						minS = Integer.parseInt(sTime.split(":", 0)[0]) * 60 + Integer.parseInt(sTime.split(":", 0)[1]);
					} else {
						minS = 0;
					}
					if (eTime != "") {
						minE = Integer.parseInt(eTime.split(":", 0)[0]) * 60 + Integer.parseInt(eTime.split(":", 0)[1]);
					} else {
						minE = 1440;
					}
					if (minE > minS) {
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

				printLineNum = 0;
				if (bOutput) {
					System.out.printf("\n\n%9s | %15s | %11s | %s\n", "Time", "UserName", "Type", "ConnectionPoint");
				}
				for (int i = 0; i < httplog.size(); i++) {
					httplogArr = httplog.get(i);
					packetInfo = httplogArr.get(urlC.pakcetInfo).split(" ", 0);
					logTime = Integer.parseInt(httplogArr.get(urlC.time).split(":", 0)[0]) * 60
							+ Integer.parseInt(httplogArr.get(urlC.time).split(":", 0)[1]);
					if ((bUserName == httplogArr.get(urlC.User).contains(UserName) || UserName == "")
							&& (bHttpMethod == packetInfo[1].contains(httpMethod) || httpMethod == "")
							&& (bTargetUrl == packetInfo[2].contains(targetUrl) || targetUrl == "") && minS <= logTime
							&& minE >= logTime) {

						if (bOutput) {
							System.out.printf("%9s | %15s | %11s | %s\n",
									httplogArr.get(urlC.time).split(Pattern.quote("."), 0)[0],
									httplogArr.get(urlC.User).split("-", 0)[1], packetInfo[1].split("=", 0)[1],
									packetInfo[2].split("=", 2)[1]);
						}
						printLineNum++;
					}
				}
				System.out.printf("\n%8d / %8d (%3f %%)\n\n", printLineNum, httpLineNum,
						(float) printLineNum / httpLineNum * 100.0);

				while (true) {
					retry = inputStrData("検索条件を指定し直しますか(y/n)");
					if (retry.equals("y") || retry.equals("n")) {
						break;
					}
				}
				if (retry.equals("n")) {
					packetInfo = null;
					UserName = null;
					targetUrl = null;
					httpMethod = null;
					retry = null;
					httplogArr.clear();
					httplog.clear();
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