package shop.HealthJava.vo;

import lombok.Getter;
import lombok.Setter;
import lombok.ToString;

@Setter
@Getter
@ToString
public class MemberVO { /* 되도록이면 member 테이블 컬럼명과 일치하는 빈클래스 변수명을 정의, 데이터 저장빈 클래스 */

	private int user_no;//회원 번호
	private String user_id; // 회원아이디
	private String user_pwd; // 비번
	private String user_name; // 회원이름
	private String user_birth; // 회원생년월일
	private String user_gender; // 회원성별 (male, female)
	private String postCode; // 우편번호
	private String roadAddr; // 도로명주소
	private String detailAddr; // 상세주소
	private String user_email; // 회원이메일
	private String user_phone; // 폰번호
	private int user_state = 0; // 가입회원이면 0, 블랙리스트 1, 탈퇴회원이면 2, 카카오 회원:3, 비회원:4
	private String join_date; // 가입날짜
	private String del_date; // 탈퇴날짜
	private String del_cont; // 탈퇴사유
	private String mail_key; //메일인증키
	private int mail_auth; //메일인증 완료:1, 인증안받았으면:0
	// 관리자 회원목록에서 페이징(쪽나누기) 관련변수
	private int startrow; // 시작행 번호
	private int endrow; // 끝행번호

	//검색필드
	private String search_type; //검색 필터(타입)
	private String search_field; //검색 입력필드

}

