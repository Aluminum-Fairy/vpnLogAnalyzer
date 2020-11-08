import java.io.*;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Scanner;
import java.util.regex.Pattern;

import logConst.urlConst;

public class vpnPacketLogAnalyzer {
	public static void main(String[] args) {

		urlConst urlC = new urlConst();

		String UserName, logline, targetUrl, retry, httpMethod, sTime, eTime;
		String packetInfo[] = new String[3];
		File fname;
		int lineNum, httpLineNum, minS, minE, printLineNum,logTime;
		boolean bTargetUrl,bUserName,bHttpMethod;
		final String version = "1.03.0";
		ArrayList<String> logArr = new ArrayList<String>();
		ArrayList<String> httplogArr = new ArrayList<String>();
		ArrayList<ArrayList<String>> httplog = new ArrayList<ArrayList<String>>();

		while (true) {
			cslClear();
			System.out.printf("%5s+-----------------------------------------+\n", "");
			System.out.printf("%5s|   SoftEther VPN Log Analyzer JAVA Ver   |\n", "");
			System.out.printf("%5s+-----------------------------------------+\n", "");
			System.out.printf("%25s %s\n\n", "Version",version);
			File list = new File("./PacketLog/");
			File files[] = list.listFiles();
			Arrays.sort(files);
			while (true) {
				for (int i = files.length-1; i >=0 ; i--) {
					System.out.printf("%3d | %30s | %4.3fMB\n", files.length - i, files[i], files[i].length() / 1024.0 / 1024.0);
				}
				try {
					fname = files[files.length - inputNumData("ファイルを選択(番号)")];
					break;
				} catch (ArrayIndexOutOfBoundsException e) {
					cslClear();
					System.out.println("ファイルのロードに失敗しました");
				}
			}
			cslClear();
			System.out.printf("選択されたファイル:%s\nロード中...", fname);
			lineNum = 0;
			try {
				byte[] data = new byte[(int) fname.length()];
				BufferedInputStream bis = new BufferedInputStream(new FileInputStream(fname));
				bis.read(data);
				bis.close();
				String fs = new String(data, "utf-8");
				String[] fsArr = fs.split("\n", 0);
				for (; lineNum < fsArr.length; lineNum++) {
					logArr.add(fsArr[lineNum]);
				}
				data = null;
				fs = null;
				fsArr = null;
				fname = null;
			} catch (Exception e) {
				System.out.println("ロードに失敗しました:" + e);
				System.exit(1);
			}

			System.out.print("完了\n  展開中...");
			String[] logtmp;
			httpLineNum = 0;
			for (int i = 0; i < logArr.size(); i++) {
				logline = logArr.get(i);
				if (logline.contains("HttpUrl")) {
					ArrayList<String> loglinetmp = new ArrayList<String>();
					logtmp = logArr.get(i).split(",", 0);
					for (int j = 0; j < logtmp.length; j++) {
						loglinetmp.add(logtmp[j]);
					}
					httpLineNum++;
					httplog.add((ArrayList<String>) loglinetmp);
				}
			}
			logtmp = null;
			logline = null;
			logArr.clear();

			System.out.printf("完了\n%10s:%8d\n%8s:%8d\n", "ログ行数", lineNum, "検索対象行数", httpLineNum);

			while (true) {
				UserName = inputStrData("\n検索対象ユーザー名");
				if(UserName != ""){
					bUserName = !UserName.substring(0,1).contains("!");
					if(!bUserName){
						UserName = UserName.substring(1);
					}
				}else{
					bUserName = true;
				}
				targetUrl = inputStrData("検索対象URL");
				if(targetUrl !=""){
					bTargetUrl = !targetUrl.substring(0, 1).contains("!");
					if(!bTargetUrl){
						targetUrl = targetUrl.substring(1);
					}
				}else{
					bTargetUrl = true;
				}
				httpMethod = inputStrData("Connection Type");
				if(httpMethod !=""){
					bHttpMethod = !httpMethod.substring(0,1).contains("!");
					if(!bHttpMethod){
						httpMethod = httpMethod.substring(1);
					}
				}else{
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

				printLineNum = 0;
				System.out.printf("\n\n%9s | %15s | %11s | %s\n", "Time", "UserName", "Type", "ConnectionPoint");
				for (int i = 0; i < httplog.size(); i++) {
					httplogArr = httplog.get(i);
					packetInfo = httplogArr.get(urlC.pakcetInfo).split(" ", 0);
					logTime =  	Integer.parseInt(httplogArr.get(urlC.time).split(":", 0)[0]) * 60+
								Integer.parseInt(httplogArr.get(urlC.time).split(":", 0)[1]);
					if ((bUserName == httplogArr.get(urlC.User).contains(UserName) || UserName == "")
							&& (bHttpMethod == packetInfo[1].contains(httpMethod) || httpMethod == "")
							&& (bTargetUrl == packetInfo[2].contains(targetUrl) || targetUrl == "")
							&& minS <= logTime
							&& minE >= logTime) {

						System.out.printf("%9s | %15s | %11s | %s\n",
								httplogArr.get(urlC.time).split(Pattern.quote("."), 0)[0],
								httplogArr.get(urlC.User).split("-", 0)[1],
								packetInfo[1].split("=", 0)[1],
								packetInfo[2].split("=", 2)[1]);
						printLineNum++;
					}
				}
				System.out.printf("\n%8d / %8d\n\n", printLineNum, httpLineNum);

				while (true) {
					retry = inputStrData("検索条件を指定し直しますか(y/n)");
					if (retry.contains("y") || retry.contains("n")) {
						break;
					}
				}
				if (retry.contains("n")) {
					packetInfo = null;
					UserName = null;
					targetUrl = null;
					httpMethod = null;
					retry = null;
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
		} else if (input.equals("-1")) {
			return "";
		}
		return input;
	}

	static void cslClear() {
		System.out.print("\033[H\033[2J");
		System.out.flush();
	}

}