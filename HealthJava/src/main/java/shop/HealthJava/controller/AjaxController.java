package shop.HealthJava.controller;

import java.util.List;

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
import shop.HealthJava.vo.ProductVO;

@Controller
public class AjaxController {

	@Autowired
	private AdminService adminService;
	

	/*회원 목록 AJAX
	 * 
	 */
	//Ajax 회원관리 데이터 Response
	@ResponseBody
	@RequestMapping(value = "/member_search")
	public List<MemberVO> member_search (Model model, MemberVO mvo, String search_field, String search_type) throws Exception{
		
		search_field = "%" + search_field + "%" ;
		
		System.out.println("search_type : " + search_type);
		System.out.println("search_field : " + search_field);
		
		mvo.setSearch_type(search_type);
		mvo.setSearch_field(search_field);
			
		List<MemberVO> mlist = this.adminService.getMemberListBySearch(mvo);			
		System.out.println(mlist);
		model.addAttribute("mlist", mlist);
		return mlist;
	}
	
	@ResponseBody
	@RequestMapping(value = "/CSBoard_search")
	public List<CSClientVO> CSBoard_search (Model model, CSClientVO cvo, String search_field, String search_type) throws Exception{
		
		search_field = "%" + search_field + "%" ;
		
		System.out.println("search_type : " + search_type);
		System.out.println("search_field : " + search_field);
		
		cvo.setSearch_type(search_type);
		cvo.setSearch_field(search_field);
		
		List<CSClientVO> clist = this.adminService.getCSBoardListBySearch(cvo);			
		System.out.println(clist);
		model.addAttribute("clist", clist);
		return clist;
	}
	
	@ResponseBody
	@RequestMapping(value = "/product_search")
	public List<ProductVO> product_search (Model model, ProductVO pvo, String search_field, String search_type) throws Exception{
		
		search_field = "%" + search_field + "%" ;
		
		System.out.println("search_type : " + search_type);
		System.out.println("search_field : " + search_field);
		
		pvo.setSearch_type(search_type);
		pvo.setSearch_field(search_field);
		
		List<ProductVO> plist = this.adminService.getProductListBySearch(pvo);			
		System.out.println(plist);
		model.addAttribute("plist", plist);
		return plist;
	}

}
