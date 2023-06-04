package shop.HealthJava.service;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import shop.HealthJava.dao.AdminDAO;
import shop.HealthJava.vo.CSClientVO;
import shop.HealthJava.vo.MemberVO;
import shop.HealthJava.vo.OrderDetailVO;
import shop.HealthJava.vo.OrderVO;
import shop.HealthJava.vo.ProductQnAVO;
import shop.HealthJava.vo.ProductVO;

@Service
public class AdminServiceImpl implements AdminService {
	
	@Autowired
	private AdminDAO adminDao;
	
	//관리자 - 회원 정보 조회
	@Override
	public List<MemberVO> getMemberListBySearch(MemberVO mvo) {
		return this.adminDao.getMemberListBySearch(mvo);
	}

	//관리자 - 검색에 따른 회원수
	@Override
	public int getMemberCount(MemberVO mvo) {
		return this.adminDao.getMemberCount(mvo);
	}

	//관리자 - 회원번호에 따른 정보조회
	@Override
	public MemberVO getMemberInfo(int user_no) {
		return this.adminDao.getMemberInfo(user_no);
	}

	//관리자 - 회원정보 수정
	@Override
	public int MemberEdit(MemberVO mvo) {
		return this.adminDao.MemberEdit(mvo);
	}

	//관리자 - 검색에 따른 상품수
	@Override
	public int getProductCount(ProductVO pvo) {
		return this.adminDao.getProductCount(pvo);
	}

	//관리자 - 상품 리스트 조회
	@Override
	public List<ProductVO> getProductListBySearch(ProductVO pvo) {
		return this.adminDao.getProductListBySearch(pvo);
	}

	//관리자 - 문의게시판 글 개수
	@Override
	public int getCSBoardCount(CSClientVO cvo) {
		return this.adminDao.getCSBoardCount(cvo);
	}

	//관리자 - 문의게시판 리스트 조회
	@Override
	public List<CSClientVO> getCSBoardListBySearch(CSClientVO cvo) {
		return this.adminDao.getCSBoardListBySearch(cvo);
	}

	//관리자 - 문의게시판 내용보기
	@Override
	public CSClientVO getClientCont(int client_no) {
		return this.adminDao.getClientCont(client_no);
	}

	//관리자 - 문의게시판 댓글ok
	@Override
	public int replyBoard(CSClientVO cvo) {
		return this.adminDao.replyBoard(cvo);
	}

	//관리자 - 회원유형 수정(블랙리스트)
	@Override
	public int MemberBlack(MemberVO mvo) {
		return this.adminDao.MemberBlack(mvo);
	}

	//관리자 - 상품 리스트 개수
	@Override
	public int getListCount(ProductVO pvo) {
		return this.adminDao.getListCount(pvo);
	}

	//관리자 - 상품 QNA 리스트 개수
	@Override
	public int getGsQNACount(ProductQnAVO qvo) {
		return this.adminDao.getGsQNACount(qvo);
	}

	//관리자 - 상품 QNA 목록 조회
	@Override
	public List<ProductQnAVO> getGsQNAListBySearch(ProductQnAVO qvo) {
		return this.adminDao.getGsQNAListBySearch(qvo);
	}

	//관리자 - 상품 QNA 게시판 내용보기
	@Override
	public ProductQnAVO getGsQNACont(int qna_no) {
		return this.adminDao.getGsQNACont(qna_no);
	}

	//관리자 - 상품 QNA 게시판 댓글ok
	@Override
	public void replyGsQNA(ProductQnAVO qvo) {
		this.adminDao.replyGsQNA(qvo);
	}

	//관리자 - 총 주문 건수
	@Override
	public int getAllOrderCount() {
		return this.adminDao.getAllOrderCount();
	}

	//관리자 - 총 주문 목록
	@Override
	public List<OrderVO> getAllOrderList() {
		return this.adminDao.getAllOrderList();
	}

	//관리자 - 번호기준 주문내역 보기
	@Override
	public OrderVO getOrderByNo(int order_no) {
		return this.adminDao.getOrderByNo(order_no);
	}

	//관리자 - 주문 상세내역 보기
	@Override
	public List<OrderDetailVO> getOrderDetailByNo(int order_no) {
		return this.adminDao.getOrderDetailByNo(order_no);
	}

	//관리자 - 송장번호 입력
	@Override
	public int updateInvoice(OrderVO ovo) {
		return this.adminDao.updateInvoice(ovo);
	}
	
}
