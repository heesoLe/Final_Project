package shop.HealthJava.controller;

import java.util.ArrayList;
import java.util.Calendar;
import java.util.List;
import java.util.Map;
import java.util.Random;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.servlet.ModelAndView;

import shop.HealthJava.service.MemberService;
import shop.HealthJava.service.MypageService;
import shop.HealthJava.vo.AddrVO;
import shop.HealthJava.vo.CartVO;
import shop.HealthJava.vo.LikeVO;
import shop.HealthJava.vo.MemberVO;
import shop.HealthJava.vo.OrderDetailVO;
import shop.HealthJava.vo.OrderVO;
import shop.HealthJava.vo.ReviewsVO;

@Controller
public class MypageController {
	
	@Autowired
	private MypageService myPageService;
	
	@Autowired
	private MemberService memberService;
	
	
	//마이페이지 메인화면
	@RequestMapping("/myPage_Main")
	public String myPage_Main(OrderVO ovo,Model model, HttpServletRequest request, HttpServletResponse response, HttpSession session ) {
		String user_id = (String)session.getAttribute("session_id");
		if(user_id==null) {
			
			return "/member/member_login";
		}
		ovo.setUser_id(user_id);
		System.out.println(user_id);
		int order_count = this.myPageService.getOrderCount(ovo); // 총 주문 건수
		List<OrderVO> olist = this.myPageService.getOrderList(user_id); // 주문 내역 list
		
		System.out.println("주문내역 리스트 : "+olist);
		System.out.println("총 주문건수 : "+order_count);
		System.out.println("총합 : "+ovo.getOrder_total());
		request.setAttribute("order_total", ovo.getOrder_total());//test
		model.addAttribute("order_count", order_count);
		model.addAttribute("olist", olist);
		
		return "/mypage/myPage_Main";
	}
		
	// 마이페이지 주문ㆍ배송 : tbl_order (주문내역 table)
	@RequestMapping("/myPage_order")
	public String myPage_orderCancel(OrderVO ovo, Model model, HttpServletRequest request, HttpServletResponse response, HttpSession session ) {
		String user_id = (String)session.getAttribute("session_id");
		ovo.setUser_id(user_id);
		System.out.println("주문ㆍ배송 접속 중");
		
		int order_count = this.myPageService.getOrderCount(ovo); // 총 주문 건수
		List<OrderVO> olist = this.myPageService.getOrderList(user_id); // 주문 내역 list
		
		System.out.println("주문내역 리스트 : "+olist);
		System.out.println("총 주문건수 : "+order_count);
		System.out.println("총합 : "+ovo.getOrder_total());
		request.setAttribute("order_total", ovo.getOrder_total());//test
		model.addAttribute("order_count", order_count);
		model.addAttribute("olist", olist);
		//ModelAndView wm=new ModelAndView("mypage/myPage_orderCancel");//생성자 인자값으로 뷰페이지 경로 설정=>/WEB-INF/
		System.out.println("주문ㆍ배송 접속 완료닷!");
		return "/mypage/myPage_order";		
	}
	
	// 마이페이지 교환/반품/환불 : tbl_order_detail , tbl_refund (교환,환불,반품 신청용 table)
	@RequestMapping("/myPage_orderDetails")
	public String myPage_orderDetails(OrderDetailVO odv, Model model, HttpServletRequest request) {
		
		System.out.println("교환/반품/환불 접속중");
		int order_no = Integer.parseInt(request.getParameter("order_no"));
		odv.setOrder_no(order_no);
		List<OrderDetailVO> orderDetailList = this.myPageService.getOrderDetailList(odv); // 주문상세 내역 list order_no 기준
		
		System.out.println("주문 상세 내역 리스트 : "+ orderDetailList);
		System.out.println("주문내역 : "+ order_no);
		
		model.addAttribute("order_no", order_no);
		model.addAttribute("orderDetailList", orderDetailList); 
		
		//ModelAndView wm=new ModelAndView("mypage/myPage_orderDetails");//생성자 인자값으로 뷰페이지 경로 설정=>/WEB-INF/
		System.out.println("교환/반품/환불 접속 완료했당, 휴~");
		return "mypage/myPage_orderDetails";
	}

	//마이페이지 찜 : tbl_like(찜목록 table) : like_no, user_id, product_id
	@RequestMapping("/myPage_like")
	public String myPage_like(LikeVO lv, Model model, HttpServletRequest request, HttpServletResponse response, HttpSession session ) {
		
		System.out.println("찜목록 접속중");
		String user_id = (String)session.getAttribute("session_id");
		System.out.println(user_id);
				
		lv.setLike_mem_id(user_id);
		// 찜목록 조회 
		List<LikeVO> Llist = this.myPageService.getLikeProductsList(lv); 
		System.out.println("찜목록 : "+Llist);
		
		// 뷰페이지로 전달
		model.addAttribute("Llist", Llist);
		//ModelAndView wm=new ModelAndView("mypage/myPage_like");//생성자 인자값으로 뷰페이지 경로 설정=>/WEB-INF/
		System.out.println("찜목록 접속 완료다요");
		return "mypage/myPage_like";
	}
	
	@RequestMapping("/myPage_cart")
	public String myPage_basket(@ModelAttribute CartVO cvo, Model model, HttpServletRequest request, HttpServletResponse response, HttpSession session ) {
		System.out.println("장바구니 접속중");
		// 로그인 된 사용자의 정보 가져오기
		String user_id = (String)session.getAttribute("session_id");
		cvo.setCart_mem_id(user_id);
		System.out.println(user_id);
		
		List<CartVO> clist = this.myPageService.getCartList(cvo); // 장바구니 리스트 조회
		System.out.println("장바구니 목록 : "+clist);
		model.addAttribute("clist", clist);
		//ModelAndView wm=new ModelAndView("mypage/myPage_basket");//생성자 인자값으로 뷰페이지 경로 설정=>/WEB-INF/
		System.out.println("장바구니 접속 완료~");
		return "mypage/myPage_cart";
	}	
	
	//마이페이지 장바구니 상품갯수 증가
	@RequestMapping(value = "/cart_cntUp", method = { RequestMethod.POST })
	@ResponseBody
	public ModelAndView cart_cntUp(@ModelAttribute CartVO cvo, Model model, HttpServletRequest request, HttpServletResponse response, HttpSession session ) {
		System.out.println("장바구니 삭제중");
		// 로그인 된 사용자의 정보 가져오기
		String user_id = (String)session.getAttribute("session_id");
		int cart_no = Integer.parseInt(request.getParameter("cart_no"));
		cvo.setCart_mem_id(user_id);
		cvo.setCart_no(cart_no);
		System.out.println(cart_no);
		
		//this.myPageService.upCartCnt(cvo); // 장바구니 리스트 조회
		
		
		return null;
	}	
	
	//마이페이지 장바구니 개별 삭제 : tbl_cart
	@RequestMapping("/cart_del")
	public ModelAndView cart_del(@ModelAttribute CartVO cvo, Model model, HttpServletRequest request, HttpServletResponse response, HttpSession session ) {
		System.out.println("장바구니 삭제중");
		// 로그인 된 사용자의 정보 가져오기
		String user_id = (String)session.getAttribute("session_id");
		int cart_no = Integer.parseInt(request.getParameter("cart_no"));
		cvo.setCart_mem_id(user_id);
		cvo.setCart_no(cart_no);
		System.out.println(cart_no);
		
		this.myPageService.delCartList(cvo); // 장바구니 리스트 조회
		
		//ModelAndView wm=new ModelAndView("mypage/myPage_basket");//생성자 인자값으로 뷰페이지 경로 설정=>/WEB-INF/
		System.out.println("장바구니 삭제 완료~");
		ModelAndView wm=new ModelAndView();
		wm.setViewName("redirect:/myPage_cart");
		return wm;
	}	
	//마이페이지 장바구니 전체 삭제 : tbl_cart
	@RequestMapping("/cart_delall")
	public ModelAndView cart_delall(@ModelAttribute CartVO cvo, Model model, HttpServletRequest request, HttpServletResponse response, HttpSession session ) {
		System.out.println("장바구니 전체삭제중");
		// 로그인 된 사용자의 정보 가져오기
		String user_id = (String)session.getAttribute("session_id");
		
		cvo.setCart_mem_id(user_id);
		
		this.myPageService.delallCartList(cvo); // 장바구니 리스트 조회
		
		//ModelAndView wm=new ModelAndView("mypage/myPage_basket");//생성자 인자값으로 뷰페이지 경로 설정=>/WEB-INF/
		System.out.println("장바구니 전체삭제 완료~");
		ModelAndView wm=new ModelAndView();
		wm.setViewName("redirect:/myPage_cart");
		return wm;
	}	
	
	
	/*
	 * //장바구니 주문/결제 정보처리
	 * 
	 * @RequestMapping("/myPage_totalprice") public ModelAndView
	 * myPage_totalprice(String totalprice, OrderVO ovo) throws Exception { //String
	 * str = request.getParameter("totalprice").toString();
	 * 
	 * //System.out.println(str); System.out.println("이건가1?1"+totalprice);
	 * 
	 * 
	 * 
	 * String price[] = totalprice.split(",");
	 * 
	 * System.out.println(price[0].substring(6));
	 * System.out.println(price[1].substring(0, 3));
	 * 
	 * String a = price[0].substring(6)+price[1].substring(0, 3); int
	 * order_total=Integer.parseInt(a); System.out.println(order_total);
	 * ovo.setOrder_total(order_total);
	 * 
	 * ModelAndView wm=new ModelAndView();
	 * 
	 * wm.addObject("order_total", order_total);
	 * wm.setViewName("redirect:/myPagePayment"); return wm;
	 * 
	 * }
	 */
	  
	  //장바구니 주문/결제
	  @RequestMapping("/myPagePayment")
	  public ModelAndView myPagePayment(MemberVO em, OrderVO ovo, HttpServletRequest request, HttpServletResponse response, HttpSession session, Model model) throws Exception {
		  //String str = request.getParameter("totalprice").toString();
		  response.setContentType("text/html;charset=UTF-8");
		  
		  String[] check=request.getParameterValues("buy");

			String id = (String)session.getAttribute("session_id"); // 세션아이디를 구함
			em = memberService.getMember(id);
			
			//List<Integer> cart_no = new ArrayList<>();
			CartVO list = new CartVO();
			List<CartVO> list2 = new ArrayList<>();
			
		  ModelAndView wm=new ModelAndView();
		  
			
			  for(String chk : check) {
			  list = this.myPageService.getCartItem(Integer.parseInt(chk));
			  list2.add(list);
			  System.out.println(chk);
			  
			  
			  }
			 
		  
		  model.addAttribute("list", list2);
		
		  wm.setViewName("mypage/myPagePayment"); 
		  wm.addObject("em", em);
		  return wm;
	  
	  }
	  
	   //상품 바로결제
	   @RequestMapping("/PaymentOK")
	     public ModelAndView PaymentOK(MemberVO em, CartVO cvo, HttpServletRequest request, HttpServletResponse response, HttpSession session, Model model) throws Exception {
	        //String str = request.getParameter("totalprice").toString();
	        response.setContentType("text/html;charset=UTF-8");
	        
	         String id = (String)session.getAttribute("session_id"); // 세션아이디를 구함
	         em = memberService.getMember(id);
	         
	         List<CartVO> list = this.myPageService.getBuyOne(id);
	        
	        model.addAttribute("list", list);
	        ModelAndView wm=new ModelAndView();
	        wm.setViewName("mypage/myPagePayment"); 
	        wm.addObject("em", em);
	        return wm;
	     
	     }
	  
		// 주문 확정 : tbl_order, tbl_order_detail
		@RequestMapping("/order_insert_ok")
		public ModelAndView order_insert_ok(OrderVO ovo, HttpServletRequest request, HttpServletResponse response, HttpSession session, Model model) {
			response.setContentType("text/html;charset=UTF-8");
			String user_id = (String) session.getAttribute("session_id");
			ovo.setUser_id(user_id);
			System.out.println(user_id);
			int order_no;
			Calendar cal = Calendar.getInstance();// 칼렌더는 추상클래스로 new로 객체 생성을 못함. 년월일 시분초 값을 반환
			int year = cal.get(Calendar.YEAR);// 년도값
			int month = cal.get(Calendar.MONTH) + 1;// 월값, +1을 한 이유는 1월이 0으로 반환 되기 때문에
			int date = cal.get(Calendar.DATE);// 일값

			Random r = new Random();// 난수를 발생시키는 클래스
			int random = r.nextInt(100000000);// 0이상 1억 미만의 정수 숫자 난수 발생
			order_no = year + month + date + random;// 오늘 날짜 +난수

			ovo.setOrder_no(order_no);
			System.out.println(order_no);
			this.myPageService.insertOrder(ovo); //배송지 추가

			for (int i = 1; i < 10; i++) {
				String pid = request.getParameter("order_detail_pno" + i);
				String pcnt = request.getParameter("order_detail_cnt" + i);
				if (pid == null) {
					break;
				}

				System.out.println(pid);
				OrderDetailVO odvo = new OrderDetailVO();
				odvo.setOrder_no(order_no);
				odvo.setOrder_detail_mid(user_id);
				odvo.setOrder_detail_fno(Integer.parseInt(pid));
				odvo.setOrder_detail_cnt(pcnt);
				this.myPageService.insertOrderDetail(odvo);
			}

			ModelAndView wm = new ModelAndView("redirect:/myPage_order");// 생성자 인자값으로 뷰페이지 경로 설정=>/WEB-INF/

			return wm;
		}
	
	//문의 내역 확인
	/*@RequestMapping("/myPage_inquiry")
	public ModelAndView myPage_inquiry(HttpServletRequest request, HttpServletResponse response ) {
		
		ModelAndView wm=new ModelAndView("mypage/myPage_inquiry");//생성자 인자값으로 뷰페이지 경로 설정=>/WEB-INF/
		
		return wm;
	}*/
	
	
	//마이페이지 배송지 리스트 : tbl_member, tbl_addr
	@RequestMapping("/myPage_updateAddress")
	public String myPage_updateAddress(Model model, HttpSession session,HttpServletRequest request, HttpServletResponse response, @ModelAttribute MemberVO mvo, @ModelAttribute AddrVO avo ) throws Exception {
		System.out.println("배송지 리스트 접속중~");
		
		// tbl_member table : 회원 가입시 기본 주소 _user_id
		String user_id = (String) session.getAttribute("session_id"); 
		mvo.setUser_id(user_id);
		System.out.println(user_id);
		
		List<MemberVO> mlist = this.myPageService.getMemberAddrList(mvo); // 배송지 리스트 조회
		System.out.println(mlist);
		model.addAttribute("mlist", mlist);
		
		// tbl_addr : 배송지 추가 
		avo.setUser_id(user_id);
		System.out.println(user_id);
		
		List<AddrVO> alist = this.myPageService.getAddrList(avo); // 배송지 추가 리스트 조회
		System.out.println(alist);
		model.addAttribute("alist", alist);
	    
		//ModelAndView wm = new ModelAndView("mypage/myPage_updateAddress"); //생성자 인자값으로 뷰페이지 경로 설정=>/WEB-INF/
		System.out.println("배송지 리스트 접속완료했슴돠!");
		return "mypage/myPage_updateAddress";
	}

		// 마이페이지 배송지 추가 페이지 : tbl_addr
		@RequestMapping("/addr_add")
		public ModelAndView addr_add(AddrVO avo, HttpSession session, HttpServletRequest request,HttpServletResponse response) {
			response.setContentType("text/html;charset=UTF-8");
			
			 
			 
			ModelAndView wm = new ModelAndView("mypage/addr_add");// 생성자 인자값으로 뷰페이지 경로 설정=>/WEB-INF/
			return wm;
		}
	
	//마이페이지 배송지 추가 : tbl_addr
	@RequestMapping("/addr_ok")
	public ModelAndView addr_ok(AddrVO av ,HttpSession session,HttpServletRequest request, HttpServletResponse response ) throws Exception {
		response.setContentType("text/html;charset=UTF-8");
		
		 String user_id = (String) session.getAttribute("session_id");
		  av.setUser_id(user_id);
		  
		
		this.myPageService.insertAddr(av); //배송지 추가
		//ModelAndView wm = new ModelAndView("mypage/addAddressPopup"); //생성자 인자값으로 뷰페이지 경로 설정=>/WEB-INF/
		return  new ModelAndView("redirect:/myPage_updateAddress");
	}
	
	
	//마이페이지 추가 배송지 수정 : tbl_addr
	@RequestMapping("/addr_edit")
	public ModelAndView addr_edit(AddrVO avo ,HttpSession session,HttpServletRequest request, HttpServletResponse response ) throws Exception {
		response.setContentType("text/html;charset=UTF-8");
		int addr_no=Integer.parseInt(request.getParameter("addr_no"));
		avo.setAddr_no(addr_no);
		avo = this.myPageService.getOneAddr(addr_no); //배송지 내용 불러오기
		
		//ModelAndView wm = new ModelAndView("mypage/addAddressPopup"); //생성자 인자값으로 뷰페이지 경로 설정=>/WEB-INF/
		ModelAndView wm = new ModelAndView();
		wm.setViewName("/mypage/addr_edit");
		wm.addObject("addr_no", addr_no);
		wm.addObject("alist", avo);
		return wm;
				
	}
	
	//마이페이지 추가배송지 수정 버튼 : tbl_addr
	@RequestMapping("/addr_edit_ok")
	public ModelAndView addr_edit_ok(AddrVO avo ,HttpSession session,HttpServletRequest request, HttpServletResponse response ) throws Exception {
		response.setContentType("text/html;charset=UTF-8");
		int addr_no=Integer.parseInt(request.getParameter("addr_no"));
		String addr_name = request.getParameter("addr_name");
		String postCode = request.getParameter("postCode");
		String roadAddr = request.getParameter("roadAddr");
		String detailAddr = request.getParameter("detailAddr");
		
		avo.setAddr_no(addr_no);
		avo.setAddr_name(addr_name);
		avo.setPostCode(postCode);
		avo.setRoadAddr(roadAddr);
		avo.setDetailAddr(detailAddr);
		
		this.myPageService.updateAddr(avo); //배송지 내용 불러오기
		
		
		
		//ModelAndView wm = new ModelAndView("mypage/addAddressPopup"); //생성자 인자값으로 뷰페이지 경로 설정=>/WEB-INF/
		ModelAndView wm = new ModelAndView();
		wm.setViewName("redirect:/myPage_updateAddress");
		return wm;
				
	}
	
	//마이페이지 추가배송지 삭제 버튼 : tbl_addr
		@RequestMapping("/addr_del")
		public ModelAndView addr_del(HttpSession session,HttpServletRequest request, HttpServletResponse response ) throws Exception {
			response.setContentType("text/html;charset=UTF-8");
			int addr_no=Integer.parseInt(request.getParameter("addr_no"));
			
			this.myPageService.deleteAddr(addr_no); //배송지 내용 불러오기
			
			
			
			//ModelAndView wm = new ModelAndView("mypage/addAddressPopup"); //생성자 인자값으로 뷰페이지 경로 설정=>/WEB-INF/
			ModelAndView wm = new ModelAndView();
			wm.setViewName("redirect:/myPage_updateAddress");
			return wm;
					
		}
		
	
	//주문상세
	@RequestMapping("/myPage_orderCancel")
	public ModelAndView myPage_orderCancel(HttpServletRequest request, HttpServletResponse response ) {
		
		ModelAndView wm=new ModelAndView("mypage/myPage_orderCancel");//생성자 인자값으로 뷰페이지 경로 설정=>/WEB-INF/
		
		return wm;
	}
	
	// 마이페이지 리뷰 조회 : tbl_review, tbl_order_detail
	@RequestMapping("/myPage_review")
	public String myPage_review(ReviewsVO rv, OrderDetailVO odv, Model model, HttpSession session, HttpServletRequest request, HttpServletResponse response) {
		
		String user_id = (String)session.getAttribute("session_id");
		
		
		rv.setRe_mem_id("re_mem_id"); // tbl_review의 re_no 기준
		System.out.println(user_id);

		//List< Object> rlist = this.myPageService.getReviewList(user_id); // 리뷰 조회
		List<Map<String, Object>> rlist = this.myPageService.getReviewList(user_id); // 리뷰 조회
		System.out.println(rlist);
		model.addAttribute("rlist", rlist);
		
		//ModelAndView wm = new ModelAndView("mypage/myPage_review");// 생성자 인자값으로 뷰페이지 경로 설정=>/WEB-INF/
		return "mypage/myPage_review";
	}
	
	// 마이페이지 리뷰 작성 : tbl_review
	@RequestMapping("/myPage_review_write")
	public String review_write(HttpServletRequest request, HttpServletResponse response) {
		System.out.println("리뷰써야겠어!");
					
		//ModelAndView wm = new ModelAndView("mypage/myPage_review_write");// 생성자 인자값으로 뷰페이지 경로 설정=>/WEB-INF/
		System.out.println("리뷰 등록할거야?");
		return "mypage/myPage_review_write";
	}
	
	// 마이페이지 리뷰 작성 : tbl_review
	@RequestMapping("/myPage_review_write_ok")
	public ModelAndView myPage_review_write_ok(HttpServletRequest request, HttpServletResponse response) {

		ModelAndView wm = new ModelAndView("mypage/myPage_review");// 생성자 인자값으로 뷰페이지 경로 설정=>/WEB-INF/
		return wm;
	}
	
	// 마이페이지 리뷰 작성 수정 
	@RequestMapping("review_edit")
	public ModelAndView review_edit(ReviewsVO rv, Model model, HttpServletRequest request) {
		int re_no = Integer.parseUnsignedInt(request.getParameter("re_no"));
		rv.setRe_no(re_no);
		rv = this.myPageService.getOneReview(re_no); // 리뷰 등록됟 조회
		
		ModelAndView wm = new ModelAndView();
		wm.setViewName("/mypage/review_edit");
		wm.addObject("re_no", re_no);
		wm.addObject("rlist", rv);
		return wm;
	}
	
	// 마이페이지 리뷰 수정 ok 
	@RequestMapping("review_edit_ok")
	public ModelAndView review_edit_ok(ReviewsVO rv, HttpServletRequest request) {
		int re_no = Integer.parseInt(request.getParameter("re_no"));
		String re_title = request.getParameter("re_title");
		String re_content = request.getParameter("re_content");
		String re_image1 = request.getParameter("re_image1");
		String re_image2 = request.getParameter("re_image2");
		String re_image3 = request.getParameter("re_image3");
		int re_score = Integer.parseInt(request.getParameter("re_score"));
		
		rv.setRe_no(re_no);
		rv.setRe_title(re_title);
		rv.setRe_content(re_content);
		rv.setRe_image1(re_image1);
		rv.setRe_image2(re_image2);
		rv.setRe_image3(re_image3);
		rv.setRe_score(re_score);
		
		this.myPageService.updateReview(rv); // 리뷰 내용 저장
		
		ModelAndView wm = new ModelAndView();
		wm.setViewName("redirect:/myPage_review");
		return wm;
	}
	
	// 마이페이지 리뷰 삭제 
	@RequestMapping("review_del")
	public ModelAndView review_del(HttpServletRequest request) {
		int re_no = Integer.parseInt(request.getParameter("re_no"));
		
		this.myPageService.delReview(re_no); // 리뷰 삭제
		
		ModelAndView wm = new ModelAndView();
		wm.setViewName("redirect:/myPage_review");
		return wm;
	}
	
	//찜목록 삭제
	@RequestMapping("likeDel")
	public ModelAndView likeDel(HttpServletRequest request) {
		int like_no = Integer.parseInt(request.getParameter("like_no"));
		
		this.myPageService.likeDel(like_no); // 리뷰 삭제
		
		ModelAndView wm = new ModelAndView();
		wm.setViewName("redirect:/myPage_like");
		return wm;
	}
	
}
