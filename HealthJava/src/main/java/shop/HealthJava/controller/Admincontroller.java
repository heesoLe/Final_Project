package shop.HealthJava.controller;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;

import shop.HealthJava.service.AdminService;
import shop.HealthJava.vo.CSClientVO;
import shop.HealthJava.vo.MemberVO;
import shop.HealthJava.vo.OrderDetailVO;
import shop.HealthJava.vo.OrderVO;
import shop.HealthJava.vo.ProductQnAVO;
import shop.HealthJava.vo.ProductVO;

@Controller
public class Admincontroller {

	@Autowired
	private AdminService adminService;

	
	//관리자- 메인/회원관리
	@RequestMapping("/admin_main")
	public String Admin_Member(MemberVO mvo, Model model, HttpServletRequest request, HttpServletResponse response, HttpSession session) throws Exception {
		request.setCharacterEncoding("UTF-8");
		response.setContentType("html/text;charset=UTF-8");
		MemberController.isLogin(session, response);
						
		return "/admin/admin_main";

	}

	/*회원 목록 AJAX
	 * 
	 */
	//Ajax 메인페이지(회원관리, 문의게시판, 상품목록, 상품QNA 목록) 데이터 Response
	@ResponseBody
	@RequestMapping(value = "/admin_list")
	public Map<String, Object> admin_list (Model model, HttpSession session, HttpServletRequest request, HttpServletResponse response, String search_field, String search_type, String adminTab) throws Exception{
		MemberController.isLogin(session, response);
		search_field = "%" + search_field + "%" ;
		
		//회원 목록
		if(adminTab.equals("회원관리")) {
		MemberVO mvo = new MemberVO();
		mvo.setSearch_type(search_type); mvo.setSearch_field(search_field);
		List<MemberVO> mlist = this.adminService.getMemberListBySearch(mvo);		
		int member_count = this.adminService.getMemberCount(mvo);	
		Map<String, Object> paramMap = new HashMap<String, Object>();
		paramMap.put("mlist", mlist);
		paramMap.put("member_count", member_count);
		
		return paramMap;
		
		//문의글 목록
		} else if(adminTab.equals("문의게시판")) {
			CSClientVO cvo = new CSClientVO();
			cvo.setSearch_type(search_type); cvo.setSearch_field(search_field);
			int CSBoard_count = this.adminService.getCSBoardCount(cvo);			
			List<CSClientVO> clist = this.adminService.getCSBoardListBySearch(cvo);			
			Map<String, Object> paramMap = new HashMap<String, Object>();
			paramMap.put("clist", clist);
			paramMap.put("CSBoard_count", CSBoard_count);
			return paramMap;
			
		//상품 목록	
		} else if(adminTab.equals("상품목록")) {
			ProductVO pvo = new ProductVO();
			pvo.setSearch_type(search_type); pvo.setSearch_field(search_field);
			int product_count = this.adminService.getProductCount(pvo);			
			List<ProductVO> plist = this.adminService.getProductListBySearch(pvo);	
			Map<String, Object> paramMap = new HashMap<String, Object>();
			paramMap.put("plist", plist);
			paramMap.put("product_count", product_count);
			return paramMap;
			
		//상품 QNA 목록	
		} else if(adminTab.equals("상품QNA")) {
			ProductQnAVO qvo = new ProductQnAVO();
			qvo.setSearch_type(search_type); qvo.setSearch_field(search_field);
			int GsQNA_count = this.adminService.getGsQNACount(qvo);			
			List<ProductQnAVO> qlist = this.adminService.getGsQNAListBySearch(qvo);		
			Map<String, Object> paramMap = new HashMap<String, Object>();
			paramMap.put("qlist", qlist);
			paramMap.put("GsQNA_count", GsQNA_count);
			return paramMap;
		}

		else if(adminTab.equals("주문내역")) {
			int order_counts = this.adminService.getAllOrderCount(); // 총 주문 건수
			List<OrderVO> olist = this.adminService.getAllOrderList(); // 주문 내역 list
			Map<String, Object> paramMap = new HashMap<String, Object>();
			paramMap.put("olist", olist);
			paramMap.put("order_counts", order_counts);	
			return paramMap;
		}
		
		return null;
	}
	
	//회원정보 수정
	@ResponseBody
	@RequestMapping(value = "/aMember_Edit")
	public MemberVO aMember_Edit (Model model, HttpSession session, HttpServletRequest request, HttpServletResponse response) throws Exception{
		//MemberController.isLogin(session, response);
		
		int user_no = Integer.parseInt(request.getParameter("user_no"));

		MemberVO mvo = this.adminService.getMemberInfo(user_no);
		
		model.addAttribute("mvo", mvo);
		
		return mvo;
	}
	
	//회원정보 수정 ok
	@ResponseBody
	@RequestMapping(value = "/aMember_Edit_ok")
	public int aMember_Edit_ok (Model model, HttpSession session, HttpServletRequest request, HttpServletResponse response
		, String user_name, String user_birth, String user_gender, String postCode, String roadAddr // 도로명주소
		, String detailAddr, String user_email, String user_phone, String user_no) throws Exception{
		//MemberController.isLogin(session, response);
		
		int re = -1;
		
		MemberVO mvo = new MemberVO();
		mvo.setUser_no(Integer.parseInt(request.getParameter("user_no")));
		mvo.setUser_name(user_name); mvo.setUser_birth(user_birth); mvo.setUser_gender(user_gender);
		mvo.setPostCode(postCode); mvo.setRoadAddr(roadAddr); mvo.setDetailAddr(detailAddr);
		mvo.setUser_email(user_email); mvo.setUser_phone(user_phone);
		
		re = this.adminService.MemberEdit(mvo);
		
		return re;
	}
	
	//블랙리스트 수정 ok
	@ResponseBody
	@RequestMapping(value = "/aMember_Black_ok")
	public int aMember_Black_ok (Model model, HttpSession session, HttpServletRequest request, HttpServletResponse response, String user_no, String user_state) throws Exception{
		//MemberController.isLogin(session, response);
		
		int re = -1;
		
		MemberVO mvo = new MemberVO();
		mvo.setUser_no(Integer.parseInt(request.getParameter("user_no")));
		mvo.setUser_state(Integer.parseInt(request.getParameter("user_state")));
		
		re = this.adminService.MemberBlack(mvo);
		
		return re;
	}

	//1대1문의 답글
	@ResponseBody
	@RequestMapping(value = "/CSBoard_reply")
	public CSClientVO CSBoard_reply (Model model, HttpSession session, HttpServletRequest request, HttpServletResponse response) throws Exception{
		//MemberController.isLogin(session, response);
		
		int client_no = Integer.parseInt(request.getParameter("client_no"));
		System.out.println(client_no);
		
		CSClientVO cvo = this.adminService.getClientCont(client_no); // 2-2. 문의 게시판 : 내용보기 
		
		model.addAttribute("cvo", cvo);
		
		return cvo;
	}
	
	//회원정보 수정 ok
	@ResponseBody
	@RequestMapping(value = "/CSBoard_reply_ok")
	public int CSBoard_reply_ok (Model model, HttpSession session, HttpServletRequest request, HttpServletResponse response
		,String client_title, String client_cont, String user_id 
		,String client_category, String client_cont_reply) throws Exception{
		
		//MemberController.isLogin(session, response);
		
		int re = -1;
		int client_no = Integer.parseInt(request.getParameter("client_no"));
		
		CSClientVO cvo = new CSClientVO();
		cvo.setClient_no(client_no);
		cvo.setClient_title(client_title);
		cvo.setClient_cont(client_cont);
		cvo.setClient_category(client_category);
		cvo.setUser_id(user_id);
		cvo.setClient_cont_reply(client_cont_reply);	
		
		re = this.adminService.replyBoard(cvo);// 2-2.문의게시판 : 답변 저장
		
		return re;
	}
	
	//상품 QNA 답변
	@ResponseBody
	@RequestMapping(value = "/GsQNA_reply")
	public ProductQnAVO Product_QNA (Model model, HttpSession session, HttpServletRequest request, HttpServletResponse response) throws Exception{
		//MemberController.isLogin(session, response);
		
		int qna_no = Integer.parseInt(request.getParameter("qna_no"));
		
		System.out.println(qna_no);
		
		ProductQnAVO qvo = this.adminService.getGsQNACont(qna_no); // 2-2. 문의 게시판 : 내용보기 
		
		model.addAttribute("qvo", qvo);
		
		return qvo;
	}
	
	//상품 QNA 답변 ok
	@ResponseBody
	@RequestMapping(value = "/GsQNA_reply_ok")
	public int Product_QNA_ok (Model model, HttpSession session, HttpServletRequest request, HttpServletResponse response
		,String qna_title, String qna_cont, String qna_mem_id ,String qna_reply) throws Exception{

		//MemberController.isLogin(session, response);
		
		int re = -1;
		int qna_no = Integer.parseInt(request.getParameter("qna_no"));
		int qna_product_no = Integer.parseInt(request.getParameter("qna_product_no"));
		System.out.println(qna_product_no);		
		
		// 컨트롤러에서 모델 DAO로 여러개의 값을 하나의 객체로 만들어서 효율적으로 한꺼번에 전달함.
		ProductQnAVO qvo = new ProductQnAVO();
		qvo.setQna_no(qna_no);
		qvo.setQna_product_no(qna_product_no);
		qvo.setQna_title(qna_title);
		qvo.setQna_content(qna_cont);
		qvo.setQna_mem_id(qna_mem_id);
		qvo.setQna_reply(qna_reply);	
		
		this.adminService.replyGsQNA(qvo); 
		
		return re;
	}
	
	//주문 상세내역
	@ResponseBody
	@RequestMapping(value = "/order_detail")
	public List<OrderDetailVO> order_detail (Model model, HttpSession session, HttpServletRequest request, HttpServletResponse response) throws Exception{
		
		//MemberController.isLogin(session, response);
		
		int order_no = Integer.parseInt(request.getParameter("order_no"));
		
		System.out.println(order_no);
		
		List<OrderDetailVO> ovo = this.adminService.getOrderDetailByNo(order_no); 
		
		model.addAttribute("ovo", ovo);
		
		return ovo;
	}
	
	//송장번호 입력폼
	@ResponseBody
	@RequestMapping(value = "/order_invoice")
	public OrderVO order_invoice (Model model, HttpSession session, HttpServletRequest request, HttpServletResponse response) throws Exception{
		
		//MemberController.isLogin(session, response);
		
		int order_no = Integer.parseInt(request.getParameter("order_no"));
		
		System.out.println(order_no);
		
		OrderVO ovo = this.adminService.getOrderByNo(order_no); 
		
		model.addAttribute("ovo", ovo);
		
		return ovo;
	}
	
	//상품 QNA 답변 ok
	@ResponseBody
	@RequestMapping(value = "/order_invoice_ok")
	public int order_invoice_ok (Model model, HttpSession session, HttpServletRequest request, HttpServletResponse response
			,String order_invoice) throws Exception{
		
		//MemberController.isLogin(session, response);
		
		int re = -1;
		int order_no = Integer.parseInt(request.getParameter("order_no"));
		System.out.println(order_no);		
		
		// 컨트롤러에서 모델 DAO로 여러개의 값을 하나의 객체로 만들어서 효율적으로 한꺼번에 전달함.
		OrderVO ovo = new OrderVO();
		ovo.setOrder_no(order_no);
		ovo.setOrder_invoice(order_invoice);
		
		re = this.adminService.updateInvoice(ovo); 
		
		return re;
	}
	
//	// 로그인을 하지 않은 상황에서 주소창을 쳐서 들어가는것을 막고 로그인페이지로 넘기기
//	public static boolean isLogin(Model model, HttpSession session, HttpServletResponse response, HttpServletRequest request) throws Exception {
//		request.setCharacterEncoding("UTF-8");	
//		response.setContentType("text/html;charset=UTF-8");
//		PrintWriter out = response.getWriter();
//		String session_id = (String)session.getAttribute("session_id"); // 세션아이디를 구함
//		if(session_id == null) {
//			out.println("<script>");
//			out.println("alert('다시 로그인 해주세요.');"); 
//			out.println("location='member_login';");
//			out.println("</script>");
//			return false;
//		}
//		return true; // 로그인 된 경우 
//	} // end isLogin
	
	// 메인_찾아오시는길
	@RequestMapping("/location")
	public String location(MemberVO mvo, Model model, HttpServletRequest request, HttpServletResponse response, HttpSession session) throws Exception {
		request.setCharacterEncoding("UTF-8");
		response.setContentType("html/text;charset=UTF-8");
		MemberController.isLogin(session, response);
		
		return "/util/location";
		
	}
			
	// 메인_서비스 이용약관
	@RequestMapping("/service")
	public String service(Model model) {
		
		return "/util/service";
		
	}
	
	// 메인_개인정보 처리방침
	@RequestMapping("/privacy")
	public String privacy(Model model) {
		
		return "/util/privacy";
		
	}
		
	// 메인_입점/제휴문의
	@RequestMapping("/inquiry")
	public String inquiry(Model model) {
		
		return "/util/inquiry";
		
	}
	
	// 회사 소개
	@RequestMapping("/company_introduce")
	public String company_introduce(Model model) {
		
		return "/util/company_introduce";
		
	}
	
	// 메인 인증마크 
	@RequestMapping("/certificate")
	public String certificate(Model model) {
		
		return "/util/certificate";
		
	}
		
}
