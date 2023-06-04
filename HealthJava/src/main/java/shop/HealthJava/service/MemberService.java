package shop.HealthJava.service;

import java.util.HashMap;

import javax.mail.MessagingException;

import shop.HealthJava.vo.MemberVO;

public interface MemberService {

   void insertMember(MemberVO m) throws Exception;//회원저장

   void updateMember(MemberVO m); //회원정보수정완료

   
   MemberVO idCheck(String id);   //아이디중복검색

   MemberVO loginCheck(String login_id); //로그인 인증

   MemberVO idMember(MemberVO m); //id찾기

   MemberVO getMember(String id); //회원정보 불러오기

   void delMem(MemberVO dm); //회원탈퇴

   void updatePwd(MemberVO m); //비밀번호 수정

   
   void sendRandomPasswordByEmail(String user_email, String user_id, String user_name) throws MessagingException; //비밀번호 찾을 때 랜덤화된 비밀번호 이메일로 발송
   
   int updateMailAuth(MemberVO memberVo);//메일 인증키 확인 누르면 mail_auth = 1로 변경
   
   String getKakaoAccessToken(String code); //카카오 토큰받기
   
   HashMap<String, Object> getUserInfo(String access_token); //엑세스토큰으로 카카오 서버에서 유저정보 가져오기
   
   
   

   int searchEmail(Object user_email); //이메일 기준으로 카카오로 가입된 회원정보가 있는지 확인하기

   void kakaoLogout(String attribute); //카카오 로그아웃

   String getIdKakao(Object user_email);//이메일 기준으로 카카오 회원 아이디 가져오기

   MemberVO emailCheck(String user_email);//이메일 중복검사

   String emailCertification(String user_email) throws MessagingException;

   boolean verifyEmailKey(String userKey, String savedKey);


}