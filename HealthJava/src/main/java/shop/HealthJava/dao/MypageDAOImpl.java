package shop.HealthJava.dao;

import java.util.List;
import java.util.Map;

import org.apache.ibatis.session.SqlSession;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Repository;

import shop.HealthJava.vo.AddrVO;
import shop.HealthJava.vo.CartVO;
import shop.HealthJava.vo.LikeVO;
import shop.HealthJava.vo.MemberVO;
import shop.HealthJava.vo.OrderDetailVO;
import shop.HealthJava.vo.OrderVO;
import shop.HealthJava.vo.ReviewsVO;

@Repository
public class MypageDAOImpl implements MypageDAO {
	
	@Autowired
	private SqlSession sqlSession;

	// 주문 내역 list
	@Override
	public List<OrderVO> getOrderList(String user_id) {
		return this.sqlSession.selectList("order_list", user_id);
	}

	// 총 주문 건수
	@Override
	public int getOrderCount(OrderVO ovo) {
		return this.sqlSession.selectOne("order_count", ovo);
	}

	// 주문상세 내역 list order_no 기준
	@Override
	public List<OrderDetailVO> getOrderDetailList(OrderDetailVO odv) {
		return this.sqlSession.selectList("orderDetail_list", odv);
	}

	// 찜목록 조회
	@Override
	public List<LikeVO> getLikeProductList(LikeVO lv) {
		return this.sqlSession.selectList("likeP_list", lv);
	}
	
	// 장바구니 목록 조회
	@Override
	public List<CartVO> getCartList(CartVO cvo) {
		return this.sqlSession.selectList("cart_list", cvo);
	}

	// 배송지 리스트 조회
	@Override
	public List<MemberVO> getMemberAddrList(MemberVO mvo) {
		return this.sqlSession.selectList("memAddr_list", mvo);
	}

	//배송지 추가
	@Override
	public void insertAddr(AddrVO av) {
		this.sqlSession.insert("addr_in",av);
	}

	 // 배송지 추가 리스트 조회
	@Override
	public List<AddrVO> getAddrList(AddrVO avo) {
		return this.sqlSession.selectList("addr_list", avo);
	}

	//장바구니 삭제
	@Override
	public void deleteCart(CartVO cvo) {
		this.sqlSession.delete("cart_del",cvo);		
	}

	//장바구니 전체삭제
	@Override
	public void deleteAllCart(CartVO cvo) {
		this.sqlSession.delete("cart_delall",cvo);	
	}

	//추가배송지 수정 조회
	@Override
	public AddrVO selectOneAddr(int addr_no) {
		return this.sqlSession.selectOne("selectOneAddr",addr_no);
	}

	//추가 배송지 수정
	@Override
	public void updateAddr(AddrVO avo) {
		this.sqlSession.update("updateAddr", avo);
	}

	//추가 배송지 삭제
	@Override
	public void deleteAddr(int addr_no) {
		this.sqlSession.delete("deleteAddr", addr_no);
	}

	// 후기 작성
	@Override
	public void addReview(ReviewsVO rv) {
		this.sqlSession.insert("insertReview", rv);
	}

	//장바구니 체크박스 선택된 정보 조회
	@Override
	public CartVO getCartItem(int cart_no) {
		return this.sqlSession.selectOne("selectCartItem",cart_no);
	}

	// 주문확정
	@Override
	public void insertOrder(OrderVO ovo) {
		this.sqlSession.insert("insertOrder", ovo);		
	}

	//주문 상세 추가
	@Override
	public void insertOrderDetail(OrderDetailVO odvo) {
		this.sqlSession.insert("insertOrderDetail",odvo);
		
	}
	
	// 리뷰 조회
	@Override 
	public List<Map<String, Object>> getReviewList(String re_mem_id) {
		return this.sqlSession.selectList("reviewList",re_mem_id); 
	}

	// 리뷰 수정 등록됟 조회
	@Override
	public ReviewsVO getOneReview(int re_no) {
		return (ReviewsVO) this.sqlSession.selectList("review_List", re_no);
	}

	// 리뷰 내용 저장
	@Override
	public void updateReview(ReviewsVO rv) {
		this.sqlSession.update("updateReview", rv);
	}

	// 리뷰 삭제
	@Override
	public void delReview(int re_no) {
		this.sqlSession.delete("delReview", re_no);
	}

	@Override
	public List<CartVO> getBuyOne(String id) {
		return this.sqlSession.selectList("getBuyOne", id);
	}

	//찜목록 삭제
	@Override
	public void likeDel(int like_no) {
		this.sqlSession.delete("likeDel", like_no);
		
	}
}
