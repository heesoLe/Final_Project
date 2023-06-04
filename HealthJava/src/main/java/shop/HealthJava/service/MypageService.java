package shop.HealthJava.service;

import java.util.List;
import java.util.Map;

import shop.HealthJava.vo.AddrVO;
import shop.HealthJava.vo.CartVO;
import shop.HealthJava.vo.LikeVO;
import shop.HealthJava.vo.MemberVO;
import shop.HealthJava.vo.OrderDetailVO;
import shop.HealthJava.vo.OrderVO;
import shop.HealthJava.vo.ReviewsVO;

public interface MypageService {

	List<OrderVO> getOrderList(String user_id); // 주문 내역 list
	int getOrderCount(OrderVO ovo); // 총 주문 건수
	List<OrderDetailVO> getOrderDetailList(OrderDetailVO odv); // 주문상세 내역 list, order_no 기준
	List<LikeVO> getLikeProductsList(LikeVO lv); // 찜목록 조회
	
	List<CartVO> getCartList(CartVO cvo); // 장바구니 목록 조회
	void delCartList(CartVO cvo);
	void delallCartList(CartVO cvo);
	CartVO getCartItem(int cart_no); //장바구니 체크박스 선택된 정보 조회
	
	List<MemberVO> getMemberAddrList(MemberVO mvo); // 배송지 리스트 조회
	void insertAddr(AddrVO av); //배송지 추가
	List<AddrVO> getAddrList(AddrVO avo); // 배송지 추가 리스트 조회	
	AddrVO getOneAddr(int addr_no); //배송지 수정조회
	void updateAddr(AddrVO avo);//추가배송지 수정
	void deleteAddr(int addr_no);//추가배송지 삭제

	void insertOrder(OrderVO ovo); 
	void insertOrderDetail(OrderDetailVO odvo);

	//List<Object> getReviewList(String re_mem_id); // 리뷰 조회
	List<Map<String, Object>> getReviewList(String re_mem_id); // 리뷰 조회
	void addReview(ReviewsVO rv); // 후기 작성
	ReviewsVO getOneReview(int re_no); // 리뷰 등록됟 조회
	void updateReview(ReviewsVO rv); // 리뷰 내용 저장
	void delReview(int re_no); // 리뷰 삭제

	List<CartVO> getBuyOne(String id);
	void likeDel(int like_no);	 //찜목록 삭제
	
}
