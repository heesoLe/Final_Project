package shop.HealthJava.dao;

import java.util.List;

import org.apache.ibatis.session.SqlSession;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Repository;

import shop.HealthJava.vo.CSClientVO;
import shop.HealthJava.vo.MemberVO;
import shop.HealthJava.vo.OrderDetailVO;
import shop.HealthJava.vo.OrderVO;
import shop.HealthJava.vo.ProductQnAVO;
import shop.HealthJava.vo.ProductVO;

@Repository
public class AdminDAOImpl implements AdminDAO {
	
	@Autowired
	private SqlSession sqlSession;

	//관리자 - 회원 정보 조회
	@Override
	public List<MemberVO> getMemberListBySearch(MemberVO mvo) {
		return this.sqlSession.selectList("member_list", mvo);
	}
	
	//관리자 - 검색에 따른 회원수
	@Override
	public int getMemberCount(MemberVO mvo) {
		return this.sqlSession.selectOne("member_count", mvo);
	}
	
	//관리자 - 회원번호에 따른 정보조회
	@Override
	public MemberVO getMemberInfo(int user_no) {
		return this.sqlSession.selectOne("member_info", user_no);
	}

	//관리자 - 회원정보 수정
	@Override
	public int MemberEdit(MemberVO mvo) {
		return this.sqlSession.update("member_edit", mvo);
	}

	//관리자 - 검색에 따른 상품수
	@Override
	public int getProductCount(ProductVO pvo) {
		return this.sqlSession.selectOne("product_count", pvo);
	}

	//관리자 - 상품 리스트 조회
	@Override
	public List<ProductVO> getProductListBySearch(ProductVO pvo) {
		return this.sqlSession.selectList("admin_product_list", pvo);
	}

	//관리자 - 문의게시판 글 개수
	@Override
	public int getCSBoardCount(CSClientVO cvo) {
		return this.sqlSession.selectOne("CSBoard_count", cvo);
	}

	//관리자 - 문의게시판 리스트 조회
	@Override
	public List<CSClientVO> getCSBoardListBySearch(CSClientVO cvo) {
		return this.sqlSession.selectList("CSBoard_list", cvo);
	}

	//관리자 - 문의게시판 내용보기
	@Override
	public CSClientVO getClientCont(int client_no) {
		return this.sqlSession.selectOne("CSBoard_cont", client_no);
	}

	//관리자 - 문의게시판 댓글ok
	@Override
	public int replyBoard(CSClientVO cvo) {
		return this.sqlSession.update("CSBoard_reply", cvo);
	}

	//관리자 - 회원유형 수정(블랙리스트)
	@Override
	public int MemberBlack(MemberVO mvo) {
		return this.sqlSession.update("member_black", mvo);
	}

	//관리자 - 상품 리스트 개수
	@Override
	public int getListCount(ProductVO pvo) {
		return this.sqlSession.selectOne("admin_product_pageCount", pvo);
	}

	//관리자 - 상품 QNA 리스트 개수
	@Override
	public int getGsQNACount(ProductQnAVO qvo) {
		return this.sqlSession.selectOne("GsQNA_count", qvo);
	}

	//관리자 - 상품 QNA 목록 조회
	@Override
	public List<ProductQnAVO> getGsQNAListBySearch(ProductQnAVO qvo) {
		return this.sqlSession.selectList("GsQNA_list", qvo);
	}

	//관리자 - 상품 QNA 게시판 내용보기
	@Override
	public ProductQnAVO getGsQNACont(int qna_no) {
		return this.sqlSession.selectOne("GsQNA_cont", qna_no);
	}

	//관리자 - 상품 QNA 게시판 댓글ok
	@Override
	public void replyGsQNA(ProductQnAVO qvo) {
		this.sqlSession.insert("GsQNA_reply", qvo);
	}

	//관리자 - 총 주문 건수
	@Override
	public int getAllOrderCount() {
		return this.sqlSession.selectOne("order_counts");
	}

	//관리자 - 총 주문 목록
	@Override
	public List<OrderVO> getAllOrderList() {
		return this.sqlSession.selectList("order_lists");
	}

	//관리자 - 번호기준 주문내역 보기
	@Override
	public OrderVO getOrderByNo(int order_no) {
		return this.sqlSession.selectOne("orderByNo", order_no);
	}

	//관리자 - 주문 상세내역 보기
	@Override
	public List<OrderDetailVO> getOrderDetailByNo(int order_no) {
		return this.sqlSession.selectList("orderDetail_lists", order_no);
	}
	
	//관리자 - 송장번호 입력
	@Override
	public int updateInvoice(OrderVO ovo) {
		return this.sqlSession.update("invoice_update", ovo);
	}

}
