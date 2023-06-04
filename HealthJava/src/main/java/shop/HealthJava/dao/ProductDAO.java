package shop.HealthJava.dao;

import java.util.List;

import shop.HealthJava.vo.CartVO;
import shop.HealthJava.vo.LikeVO;
import shop.HealthJava.vo.OrderDetailVO;
import shop.HealthJava.vo.ProductVO;
import shop.HealthJava.vo.ProductQnAVO;

public interface ProductDAO {
	
	

	ProductVO getProductContent(int product_no);

	void insertProduct(ProductVO f);

	void deleteProduct(int product_no);

	void updateProduct(ProductVO f);
	
	public List<ProductQnAVO> getReviewList(int product_no);

	void insertQna(ProductQnAVO f);

	void insertLike(LikeVO f);

	void deldteLike(LikeVO f);

	LikeVO getLikeList(LikeVO f);

	void insertCart(CartVO c);

	void insertOrderDetail(OrderDetailVO o);

	List<ProductVO> getListNew(ProductVO f, String kind, String kind2);

	int getTotalItems(ProductVO f, String kind, String kind2);
}