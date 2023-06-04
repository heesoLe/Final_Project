package shop.HealthJava.service;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.UnsupportedEncodingException;
import java.net.HttpURLConnection;
import java.net.InetAddress;
import java.net.URL;
import java.util.HashMap;
import java.util.UUID;

import javax.mail.MessagingException;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Service;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import pwdconv.PwdChange;
import shop.HealthJava.dao.MemberDAO;
import shop.HealthJava.mail.MailHandler;
import shop.HealthJava.mail.TempKey;
import shop.HealthJava.vo.MemberVO;


@Service
public class MemberServiceImpl implements MemberService {

	@Autowired
	private MemberDAO memberDao;

	@Autowired
	private JavaMailSender mailSender;

	//회원저장
	@Override
	public void insertMember(MemberVO m) throws Exception{
		//회원가입
		this.memberDao.insertMember(m);
	}
	/*
	//메일인증키 전송
	@Override
	public void emailCertification(MemberVO member) throws MessagingException {

		String mail_key = new TempKey().getKey(30,false);//랜덤키 길이 설정
		member.setMail_key(mail_key);

		//메일인증 버튼을 클릭 시 인증을 위한 이메일 발송
		MailHandler sendMail = new MailHandler(mailSender);
		sendMail.setSubject("[HealthJava 인증메일 입니다.]"); //메일제목
		sendMail.setText(
				"<h1>HealthJava 메일인증</h1>" +
						"<br>HealthJava에 오신것을 환영합니다!" +
						"<br>아래 [이메일 인증 확인]을 눌러주세요." +
						"<br><a href='http://localhost:8282/registerEmail?user_email=" + member.getUser_email() +
						"&mail_key=" + member.getMail_key() +
						"&mail_auth=" + 1 +
				"' target='_blank'>이메일 인증 확인</a>");
		try {
			sendMail.setFrom("HealthJava123@gmail.com", "헬스자바");
		} catch (UnsupportedEncodingException | MessagingException e) {
			System.out.println("메일 전송 실패");
			e.printStackTrace();
		}
		sendMail.setTo(member.getUser_email());
		sendMail.send();
		this.memberDao.updateMailKey(member);//db에 메일키 저장

	}*/

	// 랜덤 비밀번호 이메일로 전송
	@Override
	public void sendRandomPasswordByEmail(String user_email, String user_id, String user_name) throws MessagingException {
		// 회원 정보 조회
		MemberVO member = memberDao.getMemberByEmail(user_email, user_id, user_name); //일반회원이메일을 기준으로 회원정보가져오기 

		if (member != null) {
			System.out.println("if문 들어오는거 성공!");
			// 랜덤 비밀번호 생성
			TempKey temp = new TempKey();
			String randomPassword = temp.getKey(8, true);

			// 비밀번호 암호화
			String encryptedPassword = PwdChange.getPassWordToXEMD5String(randomPassword);

			// 회원 정보 업데이트
			System.out.println("회원정보 업데이트");
			member.setUser_pwd(encryptedPassword);
			updatePwd(member);//변경된 비밀번호 저장
			System.out.println("회원정보 업데이트 성공!!!");

			// 이메일로 랜덤 비밀번호 전송
			MailHandler sendMail = new MailHandler(mailSender);
			sendMail.setSubject("[HealthJava 임시 비밀번호 안내]"); // 메일 제목
			sendMail.setText(
					"<h1>HealthJava 임시 비밀번호 안내</h1>" +
							"<br>"+ user_name +"님의 임시 비밀번호는 다음과 같습니다: " +
							"<br><strong>" + randomPassword + "</strong>");

			try {
				System.out.println("서비스 트라이");
				sendMail.setFrom("HealthJava123@gmail.com", "헬스자바");
			} catch (UnsupportedEncodingException | MessagingException e) {
				System.out.println("서비스 캐치");
				e.printStackTrace();
			}
			sendMail.setTo(user_email);
			sendMail.send();
		}

	}	

	// 이메일 인증 키 전송
	@Override
	public String emailCertification(String user_email) throws MessagingException {
		String mail_key = new TempKey().getKey(30, false);
		System.out.println("이메일 전송 서비스");
		// 메일인증 버튼을 클릭 시 인증을 위한 이메일 발송
		MailHandler sendMail = new MailHandler(mailSender);
		sendMail.setSubject("[HealthJava 인증메일 입니다.]"); // 메일 제목
		sendMail.setText(
				"<h1>HealthJava 메일인증</h1>" +
						"<br>HealthJava에 오신것을 환영합니다!" +
						"<br>아래 [이메일 인증 키]를 회원가입페이지에 입력해주세요" +
						"<br><b>[이메일 인증 키] : " + mail_key + "</b>"
				);

		try {
			System.out.println("이메일 전송합니당");
			sendMail.setFrom("HealthJava123@gmail.com", "헬스자바");

		} catch (UnsupportedEncodingException | MessagingException e) {
			System.out.println("메일 전송 실패");
			e.printStackTrace();
		}
		sendMail.setTo(user_email);
		sendMail.send();

		return mail_key; // 생성된 인증 키 반환
	}
	//인증키 비교
	@Override
	public boolean verifyEmailKey(String userKey, String savedKey) {
		if (savedKey != null && savedKey.equals(userKey)) {
			// 인증 키가 일치하면 인증 성공
			return true;
		} else {
			// 인증 키가 일치하지 않으면 인증 실패
			return false;
		}
	}

	//아이디중복 검색
	@Override
	public MemberVO idCheck(String id) {
		return this.memberDao.idCheck(id);
	}

	//로그인 인증
	@Override
	public MemberVO loginCheck(String login_id) {
		return this.memberDao.loginCheck(login_id);
	}

	//id찾기
	@Override
	public MemberVO idMember(MemberVO m) {
		return this.memberDao.findId(m);
	}




	//회원정보 불러오기
	@Override
	public MemberVO getMember(String id) {
		return this.memberDao.getMember(id);
	}

	//회원정보수정
	@Override
	public void updateMember(MemberVO m) {
		this.memberDao.updateMember(m);
	}

	//회원탈퇴
	@Override
	public void delMem(MemberVO dm) {
		this.memberDao.delMem(dm);	
	}

	//비밀번호 수정
	@Override
	public void updatePwd(MemberVO m) {
		this.memberDao.updatePwd(m);
	}

	@Override //메일 인증키 1로 변경
	public int updateMailAuth(MemberVO memberVo) {
		return this.memberDao.updateMailAuth(memberVo);
	}


	//카카오 관련된거!!!

	//카카오 엑세스 토큰 발급받기
	public String getKakaoAccessToken (String code) {
		String access_Token = "";
		String refresh_Token = "";
		String reqURL = "https://kauth.kakao.com/oauth/token";

		try {
			URL url = new URL(reqURL);
			
			HttpURLConnection conn = (HttpURLConnection) url.openConnection();
			InetAddress localhost = InetAddress.getLocalHost();//ip주소를 가져오는 코드
			
            String ipAddress = localhost.getHostAddress();
            System.out.println("아이피주소:"+ipAddress);
			//POST 요청을 위해 기본값이 false인 setDoOutput을 true로
			conn.setRequestMethod("POST");
			conn.setDoOutput(true);

			//POST 요청에 필요로 요구하는 파라미터 스트림을 통해 전송
			BufferedWriter bw = new BufferedWriter(new OutputStreamWriter(conn.getOutputStream()));
			StringBuilder sb = new StringBuilder();
			sb.append("grant_type=authorization_code");
			sb.append("&client_id=aaaaee1f55c91d357e2043134c2a017c"); // TODO REST_API_KEY 입력
			sb.append("&redirect_uri=http://localhost:8282/kakao_callback"); // TODO 인가코드 받은 redirect_uri 입력
			sb.append("&code=" + code);
			bw.write(sb.toString());
			bw.flush();

			//결과 코드가 200이라면 성공
			int responseCode = conn.getResponseCode();
			System.out.println("responseCode : " + responseCode);

			//요청을 통해 얻은 JSON타입의 Response 메세지 읽어오기
			BufferedReader br = new BufferedReader(new InputStreamReader(conn.getInputStream()));
			String line = "";
			String result = "";

			while ((line = br.readLine()) != null) {
				result += line;
			}
			System.out.println("response body : " + result);

			//Gson 라이브러리에 포함된 클래스로 JSON파싱 객체 생성
			JsonParser parser = new JsonParser();
			JsonElement element = parser.parse(result);

			access_Token = element.getAsJsonObject().get("access_token").getAsString();
			refresh_Token = element.getAsJsonObject().get("refresh_token").getAsString();

			System.out.println("access_token : " + access_Token);
			System.out.println("refresh_token : " + refresh_Token);

			br.close();
			bw.close();
		} catch (IOException e) {
			e.printStackTrace();
		}

		return access_Token;
	}


	//카카오 엑세스 토큰으로 회원정보 가져오기
	public HashMap<String, Object> getUserInfo(String accessToken) {
		HashMap<String, Object> userInfo = new HashMap<String, Object>();
		String reqUrl = "https://kapi.kakao.com/v2/user/me";
		try {
			URL url = new URL(reqUrl);
			HttpURLConnection conn = (HttpURLConnection) url.openConnection();
			conn.setRequestMethod("POST");
			conn.setRequestProperty("Authorization", "Bearer " + accessToken);
			int responseCode = conn.getResponseCode();
			System.out.println("responseCode =" + responseCode);

			BufferedReader br = new BufferedReader(new InputStreamReader(conn.getInputStream()));

			String line = "";
			String result = "";

			while((line = br.readLine()) != null) {
				result += line;
			}
			System.out.println("response body ="+result);

			JsonParser parser = new JsonParser();
			JsonElement element =  parser.parse(result);

			JsonObject properties = element.getAsJsonObject().get("properties").getAsJsonObject();
			JsonObject kakaoAccount = element.getAsJsonObject().get("kakao_account").getAsJsonObject();

			String nickname = properties.getAsJsonObject().get("nickname").getAsString();
			String email = kakaoAccount.getAsJsonObject().get("email").getAsString();
			String gender = kakaoAccount.getAsJsonObject().get("gender").getAsString();
			String newId = UUID.randomUUID().toString().substring(0, 8);//카카오회원 랜덤아이디 생성

			userInfo.put("user_id", newId);
			userInfo.put("nickname", nickname);
			userInfo.put("email", email);
			userInfo.put("gender", gender);

		} catch (Exception e) {
			e.printStackTrace();
		}
		return userInfo;
	}


	//카카오 이메일 주소로 가입된 회원이있는지 검색
	@Override
	public int searchEmail(Object user_email) {
		return memberDao.searchEmail(user_email);
	}


	//이메일 기준으로 카카오 회원 아이디 가져오기
	@Override
	public String getIdKakao(Object user_email) {
		return this.memberDao.getIdKakao(user_email);
	}


	//카카오 로그아웃
	public void kakaoLogout(String accessToken) {
		String reqURL = "http://kapi.kakao.com/v1/user/logout";
		try {
			URL url = new URL(reqURL);
			HttpURLConnection conn = (HttpURLConnection) url.openConnection();
			conn.setRequestMethod("POST");
			conn.setRequestProperty("Authorization", "Bearer " + accessToken);
			int responseCode = conn.getResponseCode();
			System.out.println("responseCode = " + responseCode);

			BufferedReader br = new BufferedReader(new InputStreamReader(conn.getInputStream()));

			String result = "";
			String line = "";

			while((line = br.readLine()) != null) {
				result+=line;
			}
			System.out.println(result);
		} catch (Exception e) {
			e.printStackTrace();
		}
	}


	//이메일 중복검사
	@Override
	public MemberVO emailCheck(String user_email) {
		return this.memberDao.emailCheck(user_email);
	}



}
