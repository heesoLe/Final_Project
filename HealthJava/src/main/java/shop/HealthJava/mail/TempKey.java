package shop.HealthJava.mail;

import java.util.Random;

// 인증번호를 보낼 때 사용하는 클래스, 이 클래스를 호출 할 때 몇 자리 수로 할 건지 사이즈를 파라미터로 보내면됨
public class TempKey {

	private boolean lowerCheck;
	private int size;
	
	public String getKey(int size, boolean lowerCheck) {
		this.size = size;
		this.lowerCheck = lowerCheck;
		return init();
	}
	
	private String init() {
		Random ran = new Random();
		StringBuffer sb = new StringBuffer();
		int num = 0;
		do {
			num = ran.nextInt(75) + 48;
			if((48 <= num && num <= 57) || (65 <= num && num <= 90) || (97 <= num && num <= 122)) {
				sb.append((char)num);
			} else {
				continue;
			}
		} while(sb.length() < size);
		if(lowerCheck) {
			return sb.toString().toLowerCase();
		}
		return sb.toString();
	}
}
