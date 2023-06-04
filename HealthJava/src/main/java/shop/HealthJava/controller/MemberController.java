package shop.HealthJava.controller;

import java.io.PrintWriter;
import java.util.HashMap;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.servlet.ModelAndView;

import pwdconv.PwdChange;
import shop.HealthJava.mail.TempKey;
import shop.HealthJava.service.MemberService;
import shop.HealthJava.vo.MemberVO;

@Controller
public class MemberController { // 사용자 관련 컨트롤러

   @Autowired
   private MemberService memberService;

   // 로그인 폼 
   @RequestMapping("/member_login") // 매핑 및 반환타입, 페이지 경로 예시
   public String member_login(HttpSession session, MemberVO member, HttpServletRequest request) {
   
       String session_id = (String) session.getAttribute("session_id");
       //ModelAndView model = new ModelAndView();
       
       if (session_id != null) {//세션아이디가 존재하면
          //model.setViewName("redirect:/myPage_Main");
          return "redirect:/product/main";
       }else {
          
          //model.setViewName("member/member_login"); //리다이렉트 금지
          return "member/member_login"; // 페이지 경로 반환
       }
       
   } // end member_login()

   // 로그인 인증 처리
   @RequestMapping("/member_login_ok")
   public ModelAndView member_login_ok(String login_id, String login_pwd, HttpServletResponse response, MemberVO member, HttpServletRequest request) throws Exception {
      response.setContentType("text/html;charset=UTF-8");
      HttpSession session = request.getSession();

      ModelAndView model = new ModelAndView();
      String checkId = request.getParameter("checkId");
      
      login_id = request.getParameter("login_id");
      if(checkId != null) {
         Cookie cookie = new Cookie("login_id", login_id);
         cookie.setMaxAge(300);
         response.addCookie(cookie);
      }
      if(checkId == null) {
         Cookie cookie = new Cookie("login_id", login_id);
         cookie.setMaxAge(0);
         response.addCookie(cookie);

      }
      
      MemberVO m = this.memberService.loginCheck(login_id); // 아이디와  상태값이 2가 아닌 경우만 로그인 인증 처리
    
      if(m == null) { // 아이디가 데이터베이스에 없을경우
         model.setViewName("forward:/member_login");
         return model;
      } else { // 회원인 경우

         // 비밀번호가 다른 경우
         if(!m.getUser_pwd().equals(PwdChange.getPassWordToXEMD5String(login_pwd))) {
        	 System.out.println("비번오류");
            model.setViewName("forward:/member_login");
            return model;
         }else { // 비밀번호가 같은 경우
        	 System.out.println("비번맞음");
            if(m.getMail_auth() != 1) {
            	
               model.setViewName("forward:/member_login");
               return model;
            }else {//로그인됬을때
               session.setAttribute("session_id", m.getUser_id()); //세션 id 키 이름에 아이디 저장
               System.out.println("안넘어감");
               model.setViewName("forward:/product/main");
               return model;

            }
         }

      }
      
   } // end member_login_ok
   

   //일반회원 로그 아웃 
   @RequestMapping("/member_logout")
   public ModelAndView member_logout(HttpServletResponse response, HttpSession session) throws Exception {

      response.setContentType("text/html;charset=UTF-8");
      PrintWriter out = response.getWriter();

      session.invalidate(); // 세션 만료  : 로그아웃 처리 

      out.println("<script>");
      out.println("alert('로그아웃 되었습니다.');"); 
      out.println("location='member_login';");
      out.println("</script>");

      return null;
   } // end member_logout

   //카카오 토큰 발급 및 로그인 처리
   @RequestMapping(value="/kakao_callback")
   public ModelAndView kakaoCallback(@RequestParam("code") String code, HttpSession session) {
      ModelAndView mav = new ModelAndView();
      // 1번 인증코드 요청 전달
      String accessToken = memberService.getKakaoAccessToken(code);
      // 2번 인증코드로 토큰 전달
      HashMap<String, Object> userInfo = memberService.getUserInfo(accessToken);
      
      System.out.println("login info : " + userInfo.toString());
      
      System.out.println("이메일"+ userInfo.get("email"));
      //String mail = (String) userInfo.get("email");
      
      int re = memberService.searchEmail(userInfo.get("email"));//db에서 이메일을 가진 회원이 있는지 확인
      String user_id = memberService.getIdKakao(userInfo.get("email"));
      
      System.out.println("가입한 user_id : " + user_id);
      System.out.println("re"+re);
      if(re == 1) {//카카오 회원인 경우
         System.out.println("이미 가입한 카카오 회원입니다");
         session.setAttribute("session_id", user_id);
         session.setAttribute("session_token", accessToken);
         mav.addObject("session_id", user_id);
         mav.setViewName("forward:/product/main");
         
      } else {//회원이 아닌경우
         mav.addObject("user_id", userInfo.get("user_id"));
         mav.addObject("user_email", userInfo.get("email"));
         mav.addObject("user_gender", userInfo.get("gender"));
         mav.addObject("user_name", userInfo.get("nickname"));
         mav.addObject("user_state", 3);
         mav.addObject("access_token", accessToken);
         
         mav.setViewName("forward:/kakao_join");
      }
   
      return mav;
   }
   
   //카카오 로그아웃
   @RequestMapping(value="/kakao_logout")
   public ModelAndView logout(HttpSession session) {
      ModelAndView mav = new ModelAndView();
      
      memberService.kakaoLogout((String)session.getAttribute("access_token"));
      session.removeAttribute("access_token");
      session.removeAttribute("session_id");
      mav.setViewName("redirect:/member_login");
      return mav;
   }
   
   // 회원가입 폼
   @RequestMapping("/member_join")
   public ModelAndView member_join(HttpServletRequest request) {

      ModelAndView jm = new ModelAndView("member/member_join");
      int user_state = 0;//일반회원가입은 0
      jm.addObject("user_state", user_state);
      System.out.println("회원가입폼!!!");
      return jm;
   } //end member_join()
   
   
   // 카카오 회원가입 폼
   @RequestMapping("/kakao_join")
   public ModelAndView kakao_join(HttpServletRequest request) {

      ModelAndView jm = new ModelAndView("member/member_join");
      System.out.println("카카오 회원가입폼!!!");
      return jm;
   } //end member_join()


   // 회원가입 완료
   @RequestMapping("/member_join_ok")
   public String member_join_ok(Model model, HttpServletRequest request, HttpServletResponse response, HttpSession session, MemberVO m) throws Exception {
      response.setContentType("text/html;charset=UTF-8");
      request.setCharacterEncoding("utf-8");
      //PrintWriter out = response.getWriter();
      System.out.println("어디서 오류난거???");
      //hidden값 불러오기
      String access_token = request.getParameter("access_token");
      int user_state = Integer.parseInt(request.getParameter("user_state"));

      System.out.println("유저값 : " + user_state);

      if(user_state != 3) { //카카오 회원이 아닐경우만 이메일인증하기   
         try {
            System.out.println("일반회원가입");
            m.setUser_pwd(PwdChange.getPassWordToXEMD5String(m.getUser_pwd()));// 비번 암호화
            user_state = 0;
            m.setUser_state(user_state);//일반회원
            System.out.println("유저값 : "+m.getUser_state());

            memberService.insertMember(m); // 회원저장
            System.out.println("일반회원가입성공");

            //memberService.emailCertification(m);
            //System.out.println("이메일성공");
            return "redirect:/member_login";

         } catch (Exception e) {
            System.out.println("회원가입실패");
         }


      } else {//카카오 회원일때만 회원가입후 바로 로그인
         System.out.println("카카오 회원가입 후 바로 로그인 성공!");

         m.setUser_state(user_state);
         m.setUser_pwd(PwdChange.getPassWordToXEMD5String(m.getUser_pwd()));// 비번 암호화
         this.memberService.insertMember(m); // 회원저장

         session.setAttribute("session_id", m.getUser_id());
         session.setAttribute("session_token", access_token);
         model.addAttribute("session_id", m.getUser_id());

         return "redirect:/product/index";

      }


      return null;
   } //end member_join_ok()

   // 아이디 중복 검색 
   @RequestMapping("/member_idcheck")
   public ModelAndView member_idcheck(String id, HttpServletResponse response) throws Exception {
      response.setContentType("text/html;charset=UTF-8");
      PrintWriter out = response.getWriter();
      
      MemberVO db_id = this.memberService.idCheck(id); // 아이디에 해당하는 회원정보를 DB로 부터 검색
      
      int re = -1;// 중복 아이디가 없을때 반환값
      
      if (db_id != null) { // 중복 아이디가 있는 경우
         re = 1;
      }
      out.println(re);// 값 반환
      
      return null;
   } //end member_idcheck()
   
   // 이메일 중복 검색 
      @RequestMapping("/emailCheck")
      public ModelAndView emailCheck(String user_email, HttpServletResponse response) throws Exception {
         response.setContentType("text/html;charset=UTF-8");
         PrintWriter out = response.getWriter();
         
         MemberVO db = this.memberService.emailCheck(user_email); // 아이디에 해당하는 회원정보를 DB로 부터 검색
         
         int re = -1;// 중복 아이디가 없을때 반환값
         
         if (db != null) { // 중복 아이디가 있는 경우
            re = 1;
         }
         
         out.println(re);// 값 반환 아작스 때문에 필요
         
         return null;
      } //end member_idcheck()

   //이메일인증
   @RequestMapping("/registerEmail")
   public ModelAndView emailConfirm(MemberVO memberVo) throws Exception{

      memberService.updateMailAuth(memberVo);
      ModelAndView em = new ModelAndView("member/member_login");
      return em;
   }

   // 비밀번호 찾기 폼
   @RequestMapping("/find_pw")
   public String forgotPasswordForm() {
      return "member/find_pw";
   }

   // 비밀번호 찾기 처리
   @RequestMapping("/find_pw_ok")
   @ResponseBody
   public String forgotPasswordSubmit(@RequestParam("user_email") String user_email,@RequestParam("user_id") String user_id,@RequestParam("user_name") String user_name,
         HttpServletRequest request, HttpServletResponse response) throws Exception {
      response.setContentType("text/html;charset=UTF-8");
      request.setCharacterEncoding("utf-8");
      String result = "false";

      try {
         memberService.sendRandomPasswordByEmail(user_email, user_id, user_name);
         // 일치하는 회원 정보가 있는 경우
         result = "true";
         System.out.println("성공성공");
         return result;
      } catch (Exception e) {
         // 일치하는 회원 정보가 없는 경우
         result = "false";
         System.out.println("실패실패");
         return result;
      }

   }

   //id찾기폼
   @RequestMapping("/find_id")
   public ModelAndView pwd_find() {
      return new ModelAndView("member/find_id");
   } // end pwd_find()

   // id찾기 결과
   @RequestMapping("/find_id_ok")
   public ModelAndView find_id_ok(@RequestParam("username") String username, String userphone, HttpServletResponse response, MemberVO m) throws Exception {
      response.setContentType("text/html;charset=UTF-8");
      PrintWriter out = response.getWriter();

      m.setUser_name(username);
      m.setUser_phone(userphone);
      MemberVO pm = this.memberService.idMember(m); // 아이디와 회원이름을 기준으로 DB로 부터 회원정보 검색

      if(pm == null) { // 회원 정보가 없는 경우
         out.println("<script>");
         out.println("alert('회원으로 검색되지 않습니다.\\n 올바른 회원정보를 입력해주세요.');"); // \\n: 엔터키와 동일하다.
         out.println("history.back();");
         out.println("</script>");
      } else { // 회원 정보가 있는 경우 

         ModelAndView fm = new ModelAndView("member/find_id_ok"); // 생성자 인자값으로 뷰페이지 경로와 파일명 설정
         fm.addObject("findId", pm.getUser_id());
         System.out.println("아이디 : "+pm.getUser_id());
         return fm;
      }
      return null;
   } // end pwd_find_ok()

   // 회원 정보 수정폼 
   @RequestMapping("/myPage_updateInfo")
   public ModelAndView member_edit(HttpServletResponse response, HttpSession session) throws Exception {
      response.setContentType("text/html;charset=UTF-8");

      String user_id = (String)session.getAttribute("session_id"); // 세션아이디를 구함

      if(isLogin(session, response)) { // 로그인 된 상태 : ture
         MemberVO em = this.memberService.getMember(user_id); // 아이디에 해당하는 회원정보를 구함
         ModelAndView m = new ModelAndView("mypage/myPage_updateInfo");

         m.addObject("em", em);
         //m.setViewName("mypage/myPage_updateInfo");

         return m;
      }

      return null;
   } // end member_edit


   // 정보 수정 완료 
   @RequestMapping("/member_update_ok")
   public ModelAndView member_update_ok(MemberVO m, HttpServletResponse response, HttpSession session) throws Exception {
      response.setContentType("text/html;charset=UTF-8");
      String user_id=(String)session.getAttribute("session_id");
      
      if(isLogin(session, response)) {
         ModelAndView model = new ModelAndView("redirect:/myPage_updateInfo");
         m.setUser_id(user_id);
         this.memberService.updateMember(m); // 회원 정보 수정
         return model;
      }

      return null;
   } // end member_update_ok

   //마이페이지 비밀번호 변경폼
   @RequestMapping("/myPage_changePwd")
   public ModelAndView myPage_changePwd(HttpServletResponse response, HttpSession session) throws Exception {
      response.setContentType("text/html;charset=UTF-8");

      String user_id = (String)session.getAttribute("session_id"); // 세션아이디를 구함

      if(isLogin(session, response)) { // 로그인 된 상태 : true
         MemberVO em = this.memberService.getMember(user_id); // 아이디에 해당하는 회원정보를 구함
         ModelAndView m = new ModelAndView("mypage/myPage_changePwd");

         return m;
      }

      return null;
   }

   // 비밀번호 수정 완료 
   @RequestMapping("/changePwd_ok")
   public ModelAndView myPage_changePwd_ok(MemberVO m, HttpServletResponse response, HttpSession session, String user_pwd, String new_pwd ) throws Exception {
      response.setContentType("text/html;charset=UTF-8");
      PrintWriter out = response.getWriter();
      String user_id=(String)session.getAttribute("session_id");

      if(isLogin(session, response)) {
         user_pwd = PwdChange.getPassWordToXEMD5String(user_pwd);//비밀번호 암호화
         m.setUser_pwd(PwdChange.getPassWordToXEMD5String(m.getUser_pwd())); // 정식 비밀번호 암호화
         MemberVO db_pwd = this.memberService.getMember(user_id);//db에 저장되있는 id에 해당하는 pwd
         if(!db_pwd.getUser_pwd().equals(user_pwd)) {
            out.println("<script>");
            out.println("alert('비밀번호가 다릅니다!');"); 
            out.println("history.back();");
            out.println("</script>");
         } else {
            m.setUser_id(user_id);
            new_pwd = PwdChange.getPassWordToXEMD5String(new_pwd);//비밀번호 암호화
            m.setUser_pwd(new_pwd);
            this.memberService.updatePwd(m); // 회원 정보 수정

            out.println("<script>");
            out.println("alert('비밀번호 수정이 완료 되었습니다.');"); 
            out.println("location='myPage_changePwd';");
            out.println("</script>");

         }

      }

      return null;
   } // end myPage_changePwd_ok

   // 회원 탈퇴
   @RequestMapping("/myPage_user_Withdrawal")
   public ModelAndView member_del(HttpSession session, HttpServletResponse response) throws Exception {
      response.setContentType("text/html;charset=UTF-8");
      PrintWriter out = response.getWriter();
      String user_id = (String)session.getAttribute("session_id"); // 세션아이디를 구함

      if(user_id == null) {
         out.println("<script>");
         out.println("alert('다시 로그인 해주세요.');"); 
         out.println("location='member_login';");
         out.println("</script>");
      } else {
         MemberVO dm = this.memberService.getMember(user_id);

         ModelAndView m = new ModelAndView("mypage/myPage_user_Withdrawal");
         m.addObject("dm", dm);
         return m;
      }

      return null;
   }//member_del()

   //회원탈퇴 완료
   @RequestMapping("/user_Withdrawal_ok")
   public ModelAndView member_del_ok(HttpServletResponse response, HttpSession session,
         String user_pwd, String del_cont) throws Exception{
      response.setContentType("text/html;charset=UTF-8");
      PrintWriter out = response.getWriter();
      String user_id = (String)session.getAttribute("session_id");

      if(user_id == null) {
         out.println("<script>");
         out.println("alert('접근할 수 없습니다. 로그인 후 이용해주세요');"); 
         out.println("location='member_login';");
         out.println("</script>");
      } else {
         user_pwd = PwdChange.getPassWordToXEMD5String(user_pwd);//비밀번호 암호화
         MemberVO db = this.memberService.getMember(user_id);
         
         if(!db.getUser_pwd().equals(user_pwd)) {
            out.println("<script>");
            out.println("alert('비밀번호가 다릅니다!');"); 
            out.println("history.back();");
            out.println("</script>");
         } else {
            MemberVO dm = new MemberVO();
            dm.setUser_id(user_id);
            dm.setDel_cont(del_cont);
            String random_code = new TempKey().getKey(6,false);//랜덤키 길이 설정
            random_code.toString();
            String user_email = db.getUser_email() + "@"+ random_code;//이메일이 유니크 값이기 때문에 탈퇴할때 변경해줘야 다시 가입가능하다
            dm.setUser_email(user_email);

            this.memberService.delMem(dm);//회원탈퇴

            session.invalidate();//세션만료

            out.println("<script>");
            out.println("alert('회원탈퇴했습니다!');"); 
            out.println("location='member_login'");
            out.println("</script>");
         }
      }

      return null;
   }//member_del_ok()
   
   // 로그인을 하지 않은 상황에서 주소창을 쳐서 들어가는것을 막고 로그인페이지로 넘기기
   public static boolean isLogin(HttpSession session, HttpServletResponse response) throws Exception {
      String user_id = (String)session.getAttribute("session_id"); // 세션아이디를 구함

      if(user_id == null) {
          response.setContentType("text/html; charset=UTF-8");
          PrintWriter out = response.getWriter();
          out.println("<script>alert('로그인 후 이용해주세요.'); location.href='/member_login';</script>");
          out.flush();
          return false;
      }
      return true; // 로그인 된 경우 
   } // end isLogin

}