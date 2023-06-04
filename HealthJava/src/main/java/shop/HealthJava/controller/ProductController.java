package shop.HealthJava.controller;

import java.io.File;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.Calendar;
import java.util.HashMap;
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
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.servlet.ModelAndView;

import com.oreilly.servlet.MultipartRequest;
import com.oreilly.servlet.multipart.DefaultFileRenamePolicy;

import shop.HealthJava.service.ProductService;
import shop.HealthJava.vo.CartVO;
import shop.HealthJava.vo.LikeVO;
import shop.HealthJava.vo.OrderDetailVO;
import shop.HealthJava.vo.ProductVO;
import shop.HealthJava.vo.ProductQnAVO;

@Controller
public class ProductController { // 상품 페이지 관련 컨트롤러

	@Autowired
	private ProductService productService;
	
	
	@ResponseBody
	@RequestMapping("/new/list")
	public Map<String, Object> newTest(Model model, ProductVO f, HttpSession session,
	        HttpServletRequest request, HttpServletResponse response) throws Exception {
	    
	    String kind = request.getParameter("kind");
	    String kind2 = request.getParameter("kind2");
	    String search_field = request.getParameter("search_field");
	    String search_type = request.getParameter("search_type");
	    
	    // 이전 세션 값을 가져오거나 저장
	    if (kind == null) {
	        kind = (String) session.getAttribute("kind");
	    } else {
	        session.setAttribute("kind", kind);
	        kind2 = null;
	        session.setAttribute("kind2", kind2);
	    }

	    if (kind2 == null) {
	        kind2 = (String) session.getAttribute("kind2");
	    } else {
	        session.setAttribute("kind2", kind2);
	    }

	    // 검색어 필드가 비어있지 않은 경우에만 검색 조건 추가
	    if (search_field != null && !search_field.isEmpty()) {
	        search_field = "%" + search_field + "%";
	        // SQL 쿼리문에 검색어 조건 추가
	        f.setSearch_field(search_field);
	        f.setSearch_type(search_type);
	    }
	    
	    System.out.println("kind: " + kind);
	    System.out.println("kind2: " + kind2);
	    System.out.println("searchField: " + search_field);
	    System.out.println("searchType: " + search_type);
	    
	    int page;
	    String pageStr = request.getParameter("page");
	    if (pageStr == null) {
	        page = 1;
	    } else {
	        page = Integer.parseInt(pageStr);
	        System.out.println("페이지:"+page);
	    }
	    
	    int limit = 10; // 한 페이지에 보여지는 목록 개수
	    f.setStartrow((page - 1) * limit + 1); // 시작 행 번호
	    f.setEndrow(f.getStartrow() + limit - 1); // 끝 행 번호
	    
	    int totalItems = this.productService.getTotalItems(f, kind, kind2);
	    int totalPages = (int) Math.ceil((double) totalItems / limit);
	    f.setPage_count(totalPages);
	    
	    List<ProductVO> flist = this.productService.getListNew(f, kind, kind2);
	    
	    // Map에 flist와 totalPages를 담아서 반환
	    Map<String, Object> resultMap = new HashMap<>();
	    resultMap.put("flist", flist);
	    resultMap.put("totalPages", totalPages);
	    
	    return resultMap;
	}
	
	
	
	
	
	@RequestMapping(value="/product/main")
	public String main(ProductVO b,HttpSession session, Model model,HttpServletRequest request, HttpServletResponse response) throws IOException {
		
		
		
			return "product/main";
		
	}
	
	
	@ResponseBody
	@RequestMapping(value="/product/qna")
	public int showlist(HttpSession session,Model model,HttpServletRequest request, HttpServletResponse response) throws IOException {
		
		
		String id = (String)session.getAttribute("session_id");
		
		
		
		if(id == null) {
			return 1;
		}
		
		if(id != null) {
			return 2;
		}
		return 3;
	}
	
	@ResponseBody
	@RequestMapping(value="/product/like")
	public int show(LikeVO f,CartVO s,OrderDetailVO o,HttpSession session,Model model,HttpServletRequest request, HttpServletResponse response) throws IOException {
		
		String cart_cnt = request.getParameter("cart_cnt");
		String prodcut_no = request.getParameter("product_no");
		String kind = request.getParameter("kind");
		String id = (String)session.getAttribute("session_id");
		
		String order_detail_cnt = request.getParameter("order_detail_cnt");
		String order_detail_price = request.getParameter("order_detail_price");
		String order_detail_pname = request.getParameter("order_detail_pname");
		
		
		int d = 4;
		int c = 3;
		int a = 2;
		int b = 1;
		
		//List<ProductVO2> detail2 = productService.getReviewList(Integer.parseInt(prodcut_no));
		if(kind.equals("1") ) {
			
			if(id ==null) {
				
				
				return b;
				
			}
			
			if(id != null) {
		
			f.setLike_pro_no(Integer.parseInt(prodcut_no));
			f.setLike_mem_id(id);
			
		this.productService.insertLike(f);
		
			return a;
		
			}
		}
		
		if(kind.equals("2") ) {
			
			f.setLike_pro_no(Integer.parseInt(prodcut_no));
			f.setLike_mem_id(id);
			
			this.productService.deleteLike(f);
			
			return a;
			}
			if(kind.equals("3") ) {
				
				
				if(id != null) {
			
			s.setCart_pro_no(Integer.parseInt(prodcut_no));
			s.setCart_mem_id(id);
			s.setCart_cnt(Integer.parseInt(cart_cnt));
			
			this.productService.insertCart(s);
			
			return c;
				}
				
				if(id == null) {
					/*
					String random_id = UUID.randomUUID().toString();
					
					
					
					
					s.setCart_pro_no(Integer.parseInt(prodcut_no));
					s.setCart_mem_id(random_id);
					s.setCart_cnt(Integer.parseInt(cart_cnt));
					
					
					this.productService.insertCart(s);
					*/
					return 5;
				}
				
				
			}
			
			if(kind.equals("4") ) {
				
				
				if(id != null) {
				
					s.setCart_pro_no(Integer.parseInt(prodcut_no));
					s.setCart_mem_id(id);
					s.setCart_cnt(Integer.parseInt(cart_cnt));
					
					this.productService.insertCart(s);
					
					return d;
				}
				
				if(id == null) {
					/*
					String random_id = UUID.randomUUID().toString();
					
					System.out.println("랜덤아이디:"+random_id);
					
					o.setOrder_detail_fno(Integer.parseInt(prodcut_no));
					o.setOrder_detail_mid(random_id);
					o.setOrder_detail_cnt(order_detail_cnt);
					o.setOrder_detail_pname(order_detail_pname);
					o.setOrder_detail_price(Integer.parseInt(order_detail_price));
					
					
					this.productService.insertOrderDetail(o);
					*/
					return 5;
				}
				
			}
		
		
		return a;
	}
	
	
	
	
	@RequestMapping(value="/qna/add_ok")
	public String qna_add( ProductQnAVO f ,HttpSession session,Model model,HttpServletRequest request, HttpServletResponse response) throws IOException {
		
		
		String product_no = request.getParameter("product_no");
		String id = (String)session.getAttribute("session_id");
		String title = request.getParameter("qnaTitle");
		String content = request.getParameter("qnaContent");
		
		
		if (id != null) {
		
		
		f.setQna_product_no(Integer.parseInt(product_no));
		f.setQna_mem_id(id);
		f.setQna_title(title);
		f.setQna_content(content);
		
		System.out.println(f.getQna_product_no());
		System.out.println(f.getQna_mem_id());
		System.out.println(f.getQna_title());
		System.out.println(f.getQna_content());
		
		
		 this.productService.insertQna(f);
		
		return "redirect:../product/detail/"+product_no;
		}
		if (id == null) {
			response.setContentType("text/html; charset=UTF-8");
			PrintWriter out = response.getWriter();
			out.println("<script>");
			out.println("alert('로그인을 해야합니다')");
			out.println("</script>");
			out.flush();
			
			return "member_login";
		}
		return null;
	}
	
	
			

	
	
	

	
	@RequestMapping(value="/product/detail/{product_no}")
	public String showProductDetail(@PathVariable int product_no, LikeVO f, HttpSession session, Model model,HttpServletRequest request, HttpServletResponse response)throws IOException {
		
		String id = (String)session.getAttribute("session_id");
		
	System.out.println("세션아이디:"+id);
		if ( id == null) {
			ProductVO detail = productService.getProductContent(product_no);
			
			List<ProductQnAVO> detail2 = productService.getReviewList(product_no);
			
			model.addAttribute("detail2",detail2);
			
			model.addAttribute("detail",detail);
			
			return "product/detail";
		}
		
		if (id != null) {
			
			ProductVO detail = productService.getProductContent(product_no);
			
			List<ProductQnAVO> detail2 = productService.getReviewList(product_no);
			
			model.addAttribute("detail2",detail2);
			
			model.addAttribute("detail",detail);
			
			f.setLike_mem_id(id);
			f.setLike_pro_no(product_no);
	
		if(productService.getLikeList(f) != null  ) {
			
		
		return "product/detail2";
		
		} 
		
		if(productService.getLikeList(f) == null  ){
		
		
		
			
			
		
			
			return "product/detail";
		
		
			}
		}
		return "product/detail";
	}
	
	@RequestMapping(value="/product/add", method=RequestMethod.GET)
	public String product_add(HttpSession session, Model model,HttpServletRequest request, HttpServletResponse response) throws IOException {
		
		
		
		return "/product/add";
	}
	
	/*@RequestMapping(value="/product/index", method=RequestMethod.GET)
	public String product_index(HttpSession session, Model model,HttpServletRequest request, HttpServletResponse response) throws IOException {
		return "/product/mainProduct";
	}*/
	
	
	@RequestMapping(value="/product/delete/{product_no}")
	public String boardDelete(@PathVariable int product_no, HttpSession session, Model model,HttpServletRequest request, HttpServletResponse response)throws IOException  {
			productService.deleteProduct(product_no);
			
		return "redirect:/admin_main";
	}
	
	@RequestMapping(value="/product/edit/{product_no}",method=RequestMethod.GET)
	public String product_edit(@PathVariable int product_no, HttpSession session, Model model,HttpServletRequest request, HttpServletResponse response) throws IOException {
		
		ProductVO detail = productService.getProductContent(product_no);
		
	
		model.addAttribute("detail",detail);
		
		
		return "/product/edit";
	}
	
	
	@RequestMapping(value="/product/edit_ok", method=RequestMethod.POST)
	public String product_edit_ok(ProductVO f, HttpServletRequest request) throws Exception{
		String saveFolder=request.getRealPath("upload");
		//이진파일 업로드 서버경로
		//System.out.println("이진파일 업로드 서버 실제 경로:"+saveFolder);

		int fileSize=5*1024*1024;//이진파일 업로드 최대크기
		MultipartRequest multi=null;//이진파일을 받을 참조변수

		
		
		
		multi=new MultipartRequest(request,saveFolder,fileSize,"UTF-8", new DefaultFileRenamePolicy());
		
		int product_no = Integer.parseInt(multi.getParameter("product_no"));
		
		
		
		String product_title = multi.getParameter("product_title");
		String product_price = multi.getParameter("product_price");
		String product_maker = multi.getParameter("product_maker");
		String product_type = multi.getParameter("product_type");
		String product_type2 = multi.getParameter("product_type2");
		String product_score = multi.getParameter("product_score");
		String product_count = multi.getParameter("product_count");
		

		File UpFile01 = multi.getFile("product_cont1");//첨부한 이진파일
		File UpFile02 = multi.getFile("product_cont2");
		File UpFile03 = multi.getFile("product_cont3");
		File UpFile04 = multi.getFile("product_cont4");//첨부한 이진파일
		
		File UpFile05 = multi.getFile("product_cont5");
		File UpFile06 = multi.getFile("product_cont6");
		File UpFile07 = multi.getFile("product_cont7");//첨부한 이진파일
		File UpFile08 = multi.getFile("product_cont8");
		ProductVO edit = this.productService.getProductContent(product_no);
		//을 받아옴.
		
		
			
			
		if(UpFile01 != null || UpFile02 != null || UpFile03 != null || UpFile04 != null
		|| UpFile05 != null || UpFile06 != null || UpFile07 != null || UpFile08 != null
				) {
			
			
			String fileName01 = null;
			String fileName02 = null;
			String fileName03 = null;
			String fileName04 = null;
			String fileName05 = null;
			String fileName06 = null;
			String fileName07 = null;
			String fileName08 = null;
			
			// List files 
			
			Calendar c=Calendar.getInstance();//칼렌더는 추상
			//클래스로 new로 객체 생성을 못함. 년월일 시분초 값을 반환
			int year=c.get(Calendar.YEAR);//년도값
			int month=c.get(Calendar.MONTH)+1;//월값. +1을 한
			//이유가 1월이 0으로 반환 되기 때문이다.
			int date=c.get(Calendar.DATE);//일값
			String homedir=saveFolder+"/"+year+"-"+month+"-"+date;//오늘
			//날짜 폴더 경로 저장
			File path1=new File(homedir);
			if(!(path1.exists())) {
				path1.mkdir();//오늘날짜 폴더경로를 생성
			}
			Random r=new Random();
			int random01=r.nextInt(100000000);
			int random02=r.nextInt(100000000);
			int random03=r.nextInt(100000000);
			int random04=r.nextInt(100000000);
			int random05=r.nextInt(100000000);
			int random06=r.nextInt(100000000);
			int random07=r.nextInt(100000000);
			int random08=r.nextInt(100000000);
			
			
			
			
		
			
			if(UpFile01 == null && edit.getProduct_cont1() == null) {
					fileName01 = "";
			} else if(UpFile01 == null && edit.getProduct_cont1() != null){
				fileName01 = edit.getProduct_cont1();
			} else if(UpFile01 != null){
				fileName01 = UpFile01.getName();
			}
			
			if(UpFile02 == null && edit.getProduct_cont2() == null) {
				fileName02 = "";
		} else if(UpFile02 == null && edit.getProduct_cont2() != null){
			fileName02 = edit.getProduct_cont2();
		} else if(UpFile02 != null){
			fileName02 = UpFile02.getName();
		}
			
			
			if(UpFile03 == null && edit.getProduct_cont3() == null) {
				fileName03 = "";
		} else if(UpFile03 == null && edit.getProduct_cont3() != null){
			fileName03 = edit.getProduct_cont3();
		} else if(UpFile03 != null){
			fileName03 = UpFile03.getName();
		}
			
			
			if(UpFile04 == null && edit.getProduct_cont4() == null) {
				fileName04 = "";
		} else if(UpFile04 == null && edit.getProduct_cont4() != null){
			fileName04 = edit.getProduct_cont4();
		} else if(UpFile04 != null){
			fileName04 = UpFile04.getName();
		}
			
			
			if(UpFile05 == null && edit.getProduct_cont5() == null) {
				fileName05 = "";
		} else if(UpFile05 == null && edit.getProduct_cont5() != null){
			fileName05 = edit.getProduct_cont5();
		} else if(UpFile05 != null){
			fileName05 = UpFile05.getName();
		}
			
			
			if(UpFile06 == null && edit.getProduct_cont6() == null) {
				fileName06 = "";
		} else if(UpFile06 == null && edit.getProduct_cont6() != null){
			fileName06 = edit.getProduct_cont6();
		} else if(UpFile06 != null){
			fileName06 = UpFile06.getName();
		}
			
			
			if(UpFile07 == null && edit.getProduct_cont7() == null) {
				fileName07 = "";
		} else if(UpFile07 == null && edit.getProduct_cont7() != null){
			fileName07 = edit.getProduct_cont7();
		} else if(UpFile07 != null){
			fileName07 = UpFile07.getName();
		}
			
			
			if(UpFile08 == null && edit.getProduct_cont8() == null) {
				fileName08 = "";
		} else if(UpFile08 == null && edit.getProduct_cont8() != null){
			fileName08 = edit.getProduct_cont8();
		} else if(UpFile08 != null){
			fileName08 = UpFile08.getName();
		}
			
			
		

			

			

			
			


			/*첨부 파일 확장자 구함*/
			int index01=fileName01.lastIndexOf(".");//마침표 위치
			int index02=fileName02.lastIndexOf(".");//마침표 위치
			int index03=fileName03.lastIndexOf(".");//마침표 위치
			int index04=fileName04.lastIndexOf(".");//마침표 위치
			int index05=fileName05.lastIndexOf(".");//마침표 위치
			int index06=fileName06.lastIndexOf(".");//마침표 위치
			int index07=fileName07.lastIndexOf(".");//마침표 위치
			int index08=fileName08.lastIndexOf(".");//마침표 위치
		
			//번호를 구함
			String fileExtension01=fileName01.substring(index01+1);//마침표
			String fileExtension02=fileName02.substring(index02+1);//마침표
			String fileExtension03=fileName03.substring(index03+1);//마침표
			String fileExtension04=fileName04.substring(index04+1);//마침표
			String fileExtension05=fileName05.substring(index05+1);//마침표
			String fileExtension06=fileName06.substring(index06+1);//마침표
			String fileExtension07=fileName07.substring(index07+1);//마침표
			String fileExtension08=fileName08.substring(index08+1);//마침표
			
			//이후부터 마지막 문자까지 구함.첨부파일 확장자를 구함
			String refileName01 = "";
			String refileName02 = "";
			String refileName03 = "";
			String refileName04 = "";
			String refileName05 = "";
			String refileName06 = "";
			String refileName07 = "";
			String refileName08 = "";
			

			String fileDBName01 = "";
			String fileDBName02 = "";
			String fileDBName03 = "";
			String fileDBName04 = "";
			String fileDBName05 = "";
			String fileDBName06 = "";
			String fileDBName07 = "";
			String fileDBName08 = "";
			
			if(fileName01 != "" && fileName01 != edit.getProduct_cont1() ) {
				refileName01="food"+year+month+date+random01+"." + fileExtension01;//새로운 이진파일명 저장
				fileDBName01="/"+year+"-"+month+"-"+date+"/"+ refileName01;//디비에 저장될 레코드값
				UpFile01.renameTo(new File(homedir+"/"+refileName01));
			}
			

			if(fileName02 != "" && fileName02 != edit.getProduct_cont2()) {
				refileName02="food"+year+month+date+random02+"." + fileExtension02;//새로운 이진파일명 저장
				fileDBName02="/"+year+"-"+month+"-"+date+"/"+ refileName02;//디비에 저장될 레코드값
				UpFile02.renameTo(new File(homedir+"/"+refileName02));
			}

			if(fileName03 != "" && fileName03 != edit.getProduct_cont3()) {
				refileName03="food"+year+month+date+random03+"." + fileExtension03;//새로운 이진파일명 저장
				fileDBName03="/"+year+"-"+month+"-"+date+"/"+ refileName03;//디비에 저장될 레코드값
				UpFile03.renameTo(new File(homedir+"/"+refileName03));
			}
			
			
			if(fileName04 != "" && fileName04 != edit.getProduct_cont4()) {
				refileName04="food"+year+month+date+random04+"." + fileExtension04;//새로운 이진파일명 저장
				fileDBName04="/"+year+"-"+month+"-"+date+"/"+ refileName04;//디비에 저장될 레코드값
				UpFile04.renameTo(new File(homedir+"/"+refileName04));
			}
			
			if(fileName05 != "" && fileName05 != edit.getProduct_cont5()) {
				refileName05="food"+year+month+date+random05+"." + fileExtension05;//새로운 이진파일명 저장
				fileDBName05="/"+year+"-"+month+"-"+date+"/"+ refileName05;//디비에 저장될 레코드값
				UpFile05.renameTo(new File(homedir+"/"+refileName05));
			}
			
			if(fileName06 != "" && fileName06 != edit.getProduct_cont6()) {
				refileName06="food"+year+month+date+random06+"." + fileExtension06;//새로운 이진파일명 저장
				fileDBName06="/"+year+"-"+month+"-"+date+"/"+ refileName06;//디비에 저장될 레코드값
				UpFile06.renameTo(new File(homedir+"/"+refileName06));
			}
			
			if(fileName07 != "" && fileName07 != edit.getProduct_cont7()) {
				refileName07="food"+year+month+date+random07+"." + fileExtension07;//새로운 이진파일명 저장
				fileDBName07="/"+year+"-"+month+"-"+date+"/"+ refileName07;//디비에 저장될 레코드값
				UpFile07.renameTo(new File(homedir+"/"+refileName07));
			}
			
			if(fileName08 != "" && fileName08 != edit.getProduct_cont8()) {
				refileName08="food"+year+month+date+random08+"." + fileExtension08;//새로운 이진파일명 저장
				fileDBName08="/"+year+"-"+month+"-"+date+"/"+ refileName08;//디비에 저장될 레코드값
				UpFile08.renameTo(new File(homedir+"/"+refileName08));
			}
			
			
			
			
			if(fileName01 == edit.getProduct_cont1() ) {
				
				fileDBName01=edit.getProduct_cont1();
				
			}
			
			if(fileName02 == edit.getProduct_cont2() ) {
				
				fileDBName02=edit.getProduct_cont2();
				
			}

			if(fileName03 == edit.getProduct_cont3() ) {
	
				fileDBName03=edit.getProduct_cont3();
	
			}

			if(fileName04 == edit.getProduct_cont4() ) {
	
				fileDBName04=edit.getProduct_cont4();
	
			}

			if(fileName05 == edit.getProduct_cont5() ) {
	
				fileDBName05=edit.getProduct_cont5();
	
			}

			if(fileName06 == edit.getProduct_cont6() ) {
	
				fileDBName06=edit.getProduct_cont6();
	
			}

			if(fileName07 == edit.getProduct_cont7() ) {
	
				fileDBName07=edit.getProduct_cont7();
	
			}

			if(fileName08 == edit.getProduct_cont8() ) {
	
				fileDBName08=edit.getProduct_cont8();
	
			}


			//바뀌어진 이진파일로 업로드
			f.setProduct_cont1(fileDBName01); f.setProduct_cont2(fileDBName02); f.setProduct_cont3(fileDBName03); f.setProduct_cont4(fileDBName04);
			f.setProduct_cont5(fileDBName05); f.setProduct_cont6(fileDBName06); f.setProduct_cont7(fileDBName07); f.setProduct_cont8(fileDBName08);
		}else {//mybatis에서는 컬럼에 null을 insert하지 못함.
			
			
			String fileDBName01=""; String fileDBName02=""; String fileDBName03=""; String fileDBName04="";
			String fileDBName05=""; String fileDBName06=""; String fileDBName07=""; String fileDBName08="";
			
			if(edit.getProduct_cont1() != null) {//기존 첨부 파일이 있다면
	            f.setProduct_cont1(edit.getProduct_cont1());
	         } 
			
			if(edit.getProduct_cont2() != null) {//기존 첨부 파일이 있다면
	            f.setProduct_cont2(edit.getProduct_cont2());
	         } 
			
			if(edit.getProduct_cont3() != null) {//기존 첨부 파일이 있다면
	            f.setProduct_cont3(edit.getProduct_cont3());
	         } 
			
			if(edit.getProduct_cont4() != null) {//기존 첨부 파일이 있다면
	            f.setProduct_cont4(edit.getProduct_cont4());
	         } 
			
			if(edit.getProduct_cont5() != null) {//기존 첨부 파일이 있다면
	            f.setProduct_cont5(edit.getProduct_cont5());
	         } 
			
			if(edit.getProduct_cont6() != null) {//기존 첨부 파일이 있다면
	            f.setProduct_cont6(edit.getProduct_cont6());
	         } 
			
			if(edit.getProduct_cont7() != null) {//기존 첨부 파일이 있다면
	            f.setProduct_cont7(edit.getProduct_cont7());
	         } 
			
			if(edit.getProduct_cont8() != null) {//기존 첨부 파일이 있다면
	            f.setProduct_cont8(edit.getProduct_cont8());
	         } 
			
			/// 첨부된 값이 없을떄
			
			if(edit.getProduct_cont1() == null) {//기존 첨부 파일이 있다면
	            f.setProduct_cont1(fileDBName01);
	         } 
			
			if(edit.getProduct_cont2() == null) {//기존 첨부 파일이 있다면
	            f.setProduct_cont2(fileDBName02);
	         } 
			
			if(edit.getProduct_cont3() == null) {//기존 첨부 파일이 있다면
	            f.setProduct_cont3(fileDBName03);
	         } 
			
			if(edit.getProduct_cont4() == null) {//기존 첨부 파일이 있다면
	            f.setProduct_cont4(fileDBName04);
	         } 
			
			if(edit.getProduct_cont5() == null) {//기존 첨부 파일이 있다면
	            f.setProduct_cont5(fileDBName05);
	         } 
			
			if(edit.getProduct_cont6() == null) {//기존 첨부 파일이 있다면
	            f.setProduct_cont6(fileDBName06);
	         } 
			
			if(edit.getProduct_cont7() == null) {//기존 첨부 파일이 있다면
	            f.setProduct_cont7(fileDBName07);
	         } 
			
			if(edit.getProduct_cont8() == null) {//기존 첨부 파일이 있다면
	            f.setProduct_cont8(fileDBName08);
	         } 
			
			
		
			
		}

		f.setProduct_title(product_title); f.setProduct_price(product_price);
		f.setProduct_maker(product_maker); f.setProduct_type(product_type);
		f.setProduct_type2(product_type2); f.setProduct_score(product_score);
		f.setProduct_count(product_count); f.setProduct_no(product_no);

		System.out.println("확인값:"+f.getProduct_title());

		this.productService.updateProduct(f);//자료실 저장

		return "redirect:/admin_main";
		//return null;
	}//food_write_ok()
	
	
	@RequestMapping("/product/add_ok")
	public String product_add_ok(@ModelAttribute ProductVO f, HttpServletRequest request) throws Exception{
		String saveFolder=request.getRealPath("upload");
		//이진파일 업로드 서버경로
		//System.out.println("이진파일 업로드 서버 실제 경로:"+saveFolder);

		int fileSize=5*1024*1024;//이진파일 업로드 최대크기
		MultipartRequest multi=null;//이진파일을 받을 참조변수

		multi=new MultipartRequest(request,saveFolder,fileSize,"UTF-8", new DefaultFileRenamePolicy());
		String product_title = multi.getParameter("product_title");
		String product_price = multi.getParameter("product_price");
		String product_maker = multi.getParameter("product_maker");
		String product_type = multi.getParameter("product_type");
		String product_type2 = multi.getParameter("product_type2");
		String product_score = multi.getParameter("product_score");
		String product_count = multi.getParameter("product_count");
		

		File UpFile01 = multi.getFile("product_cont1");//첨부한 이진파일
		File UpFile02 = multi.getFile("product_cont2");
		File UpFile03 = multi.getFile("product_cont3");
		File UpFile04 = multi.getFile("product_cont4");//첨부한 이진파일
		
		File UpFile05 = multi.getFile("product_cont5");
		File UpFile06 = multi.getFile("product_cont6");
		File UpFile07 = multi.getFile("product_cont7");//첨부한 이진파일
		File UpFile08 = multi.getFile("product_cont8");
		
		//을 받아옴.
		if(UpFile01 != null || UpFile02 != null || UpFile03 != null || UpFile04 != null
		|| UpFile05 != null || UpFile06 != null || UpFile07 != null || UpFile08 != null
				) {//첨부한 이진파일이 있다면
			String fileName01 = null;
			String fileName02 = null;
			String fileName03 = null;
			String fileName04 = null;
			String fileName05 = null;
			String fileName06 = null;
			String fileName07 = null;
			String fileName08 = null;
			

			if(UpFile01 == null) {
				fileName01 = "";
			} else {
				fileName01 = UpFile01.getName();
			}

			if(UpFile02 == null) {
				fileName02 = "";
			} else {
				fileName02 = UpFile02.getName();
			}

			if(UpFile03 == null) {
				fileName03 = "";
			} else {
				fileName03 = UpFile03.getName();
			}
			
			if(UpFile04 == null) {
				fileName04 = "";
			} else {
				fileName04 = UpFile04.getName();
			}
			
			if(UpFile05 == null) {
				fileName05 = "";
			} else {
				fileName05 = UpFile05.getName();
			}
			
			if(UpFile06 == null) {
				fileName06 = "";
			} else {
				fileName06 = UpFile06.getName();
			}
			
			if(UpFile07 == null) {
				fileName07 = "";
			} else {
				fileName07 = UpFile07.getName();
			}
			
			if(UpFile08 == null) {
				fileName08 = "";
			} else {
				fileName08 = UpFile08.getName();
			}

			Calendar c=Calendar.getInstance();//칼렌더는 추상
			//클래스로 new로 객체 생성을 못함. 년월일 시분초 값을 반환
			int year=c.get(Calendar.YEAR);//년도값
			int month=c.get(Calendar.MONTH)+1;//월값. +1을 한
			//이유가 1월이 0으로 반환 되기 때문이다.
			int date=c.get(Calendar.DATE);//일값
			String homedir=saveFolder+"/"+year+"-"+month+"-"+date;//오늘
			//날짜 폴더 경로 저장
			File path1=new File(homedir);
			if(!(path1.exists())) {
				path1.mkdir();//오늘날짜 폴더경로를 생성
			}
			Random r=new Random();
			int random01=r.nextInt(100000000);
			int random02=r.nextInt(100000000);
			int random03=r.nextInt(100000000);
			int random04=r.nextInt(100000000);
			int random05=r.nextInt(100000000);
			int random06=r.nextInt(100000000);
			int random07=r.nextInt(100000000);
			int random08=r.nextInt(100000000);
			


			/*첨부 파일 확장자 구함*/
			int index01=fileName01.lastIndexOf(".");//마침표 위치
			int index02=fileName02.lastIndexOf(".");//마침표 위치
			int index03=fileName03.lastIndexOf(".");//마침표 위치
			int index04=fileName04.lastIndexOf(".");//마침표 위치
			int index05=fileName05.lastIndexOf(".");//마침표 위치
			int index06=fileName06.lastIndexOf(".");//마침표 위치
			int index07=fileName07.lastIndexOf(".");//마침표 위치
			int index08=fileName08.lastIndexOf(".");//마침표 위치
		
			//번호를 구함
			String fileExtension01=fileName01.substring(index01+1);//마침표
			String fileExtension02=fileName02.substring(index02+1);//마침표
			String fileExtension03=fileName03.substring(index03+1);//마침표
			String fileExtension04=fileName04.substring(index04+1);//마침표
			String fileExtension05=fileName05.substring(index05+1);//마침표
			String fileExtension06=fileName06.substring(index06+1);//마침표
			String fileExtension07=fileName07.substring(index07+1);//마침표
			String fileExtension08=fileName08.substring(index08+1);//마침표
			
			//이후부터 마지막 문자까지 구함.첨부파일 확장자를 구함
			String refileName01 = "";
			String refileName02 = "";
			String refileName03 = "";
			String refileName04 = "";
			String refileName05 = "";
			String refileName06 = "";
			String refileName07 = "";
			String refileName08 = "";
			

			String fileDBName01 = "";
			String fileDBName02 = "";
			String fileDBName03 = "";
			String fileDBName04 = "";
			String fileDBName05 = "";
			String fileDBName06 = "";
			String fileDBName07 = "";
			String fileDBName08 = "";
			

			if(fileName01 != "") {
				refileName01="food"+year+month+date+random01+"." + fileExtension01;//새로운 이진파일명 저장
				fileDBName01="/"+year+"-"+month+"-"+date+"/"+ refileName01;//디비에 저장될 레코드값
				UpFile01.renameTo(new File(homedir+"/"+refileName01));
			}

			if(fileName02 != "") {
				refileName02="food"+year+month+date+random02+"." + fileExtension02;//새로운 이진파일명 저장
				fileDBName02="/"+year+"-"+month+"-"+date+"/"+ refileName02;//디비에 저장될 레코드값
				UpFile02.renameTo(new File(homedir+"/"+refileName02));
			}

			if(fileName03 != "") {
				refileName03="food"+year+month+date+random03+"." + fileExtension03;//새로운 이진파일명 저장
				fileDBName03="/"+year+"-"+month+"-"+date+"/"+ refileName03;//디비에 저장될 레코드값
				UpFile03.renameTo(new File(homedir+"/"+refileName03));
			}
			
			
			if(fileName04 != "") {
				refileName04="food"+year+month+date+random04+"." + fileExtension04;//새로운 이진파일명 저장
				fileDBName04="/"+year+"-"+month+"-"+date+"/"+ refileName04;//디비에 저장될 레코드값
				UpFile04.renameTo(new File(homedir+"/"+refileName04));
			}
			
			if(fileName05 != "") {
				refileName05="food"+year+month+date+random05+"." + fileExtension05;//새로운 이진파일명 저장
				fileDBName05="/"+year+"-"+month+"-"+date+"/"+ refileName05;//디비에 저장될 레코드값
				UpFile05.renameTo(new File(homedir+"/"+refileName05));
			}
			
			if(fileName06 != "") {
				refileName06="food"+year+month+date+random06+"." + fileExtension06;//새로운 이진파일명 저장
				fileDBName06="/"+year+"-"+month+"-"+date+"/"+ refileName06;//디비에 저장될 레코드값
				UpFile06.renameTo(new File(homedir+"/"+refileName06));
			}
			
			if(fileName07 != "") {
				refileName07="food"+year+month+date+random07+"." + fileExtension07;//새로운 이진파일명 저장
				fileDBName07="/"+year+"-"+month+"-"+date+"/"+ refileName07;//디비에 저장될 레코드값
				UpFile07.renameTo(new File(homedir+"/"+refileName07));
			}
			
			if(fileName08 != "") {
				refileName08="food"+year+month+date+random08+"." + fileExtension08;//새로운 이진파일명 저장
				fileDBName08="/"+year+"-"+month+"-"+date+"/"+ refileName08;//디비에 저장될 레코드값
				UpFile08.renameTo(new File(homedir+"/"+refileName08));
			}


			//바뀌어진 이진파일로 업로드
			f.setProduct_cont1(fileDBName01); f.setProduct_cont2(fileDBName02); f.setProduct_cont3(fileDBName03); f.setProduct_cont4(fileDBName04);
			f.setProduct_cont5(fileDBName05); f.setProduct_cont6(fileDBName06); f.setProduct_cont7(fileDBName07); f.setProduct_cont8(fileDBName08);
		}else {//mybatis에서는 컬럼에 null을 insert하지 못함.
			String fileDBName01=""; String fileDBName02=""; String fileDBName03=""; String fileDBName04="";
			String fileDBName05=""; String fileDBName06=""; String fileDBName07=""; String fileDBName08="";
			//첨부하지 않았을때 빈공백을 저장
			f.setProduct_cont1(fileDBName01);f.setProduct_cont2(fileDBName02); f.setProduct_cont3(fileDBName03); f.setProduct_cont4(fileDBName04);
			f.setProduct_cont5(fileDBName05); f.setProduct_cont6(fileDBName06); f.setProduct_cont7(fileDBName07); f.setProduct_cont8(fileDBName08);
		}

		f.setProduct_title(product_title); f.setProduct_price(product_price);
		f.setProduct_maker(product_maker); f.setProduct_type(product_type);
		f.setProduct_type2(product_type2); f.setProduct_score(product_score);
		f.setProduct_count(product_count);

		this.productService.insertProduct(f);//자료실 저장

	
		return "redirect:/admin_main";
		//return null;
	}//food_write_ok()
}
