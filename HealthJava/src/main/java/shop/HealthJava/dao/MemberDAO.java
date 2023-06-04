package shop.HealthJava.dao;

import java.util.HashMap;

import shop.HealthJava.vo.MemberVO;

public interface MemberDAO {
	void insertMember(MemberVO m);//회원저장

	MemberVO idCheck(String id);	//아이디에 해당하는 회원정보검색

	MemberVO loginCheck(String login_id);//로그인 인증

	MemberVO findId(MemberVO m); //id찾기

	MemberVO getMember(String id);//회원정보 불러오기

	void updateMember(MemberVO m); //회원정보수정

	void delMem(MemberVO dm); //회원탈퇴

	void updatePwd(MemberVO m); //비밀번호 수정

	int updateMailAuth(MemberVO memberVo); //메일 인증키 누르면 mail_auth = 1로 수정


	int updateMailKey(MemberVO memberVo); //회원정보에 메일 인증키 저장
 
	MemberVO getMemberByEmail(String user_email, String user_id, String user_name); //일반회원이메일을 기준으로 회원정보가져오기 


	int searchEmail(Object user_email); //이메일 기준으로 카카오 회원가입되있는지 확인

	String getIdKakao(Object user_email);//이메일 기준으로 카카오 회원 아이디 가져오기

	MemberVO emailCheck(String user_email);// 이메일 중복값확인

}
