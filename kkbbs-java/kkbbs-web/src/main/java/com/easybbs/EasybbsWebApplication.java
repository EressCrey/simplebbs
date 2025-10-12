package com.easybbs;

import com.easybbs.entity.config.AppConfig;
import com.easybbs.entity.constants.Constants;
import com.easybbs.spring.ApplicationContextProvider;
import org.mybatis.spring.annotation.MapperScan;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.web.servlet.MultipartConfigFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.DependsOn;
import org.springframework.scheduling.annotation.EnableAsync;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.transaction.annotation.EnableTransactionManagement;

import javax.servlet.MultipartConfigElement;


@EnableAsync
@SpringBootApplication(scanBasePackages = {"com.easybbs"})
@MapperScan(basePackages = {"com.easybbs.mappers"})
@EnableTransactionManagement
@EnableScheduling
public class EasybbsWebApplication {

    /**
     * 启动类
     * @param args
     */
    public static void main(String[] args) {
        SpringApplication.run(EasybbsWebApplication.class, args);
    }

    /**
     * 拿配置类里的配置项
     * @DependsOn 说明这个 Bean 在创建前，必须先初始化好名为 applicationContextProvider 的 Bean。
     * 这通常是为了保证 ApplicationContextProvider 已经准备好（里面能取到 Spring 的上下文）。
     */
    @Bean
    @DependsOn({"applicationContextProvider"})
    MultipartConfigElement multipartConfigElement() {
        AppConfig appConfig = (AppConfig) ApplicationContextProvider.getBean("appConfig");
        MultipartConfigFactory factory = new MultipartConfigFactory();
        /**
         * MultipartConfigFactory 是 Spring Boot 提供的一个工厂类，用于创建 MultipartConfigElement。
         * MultipartConfigElement 是标准 Servlet 的配置对象，用于定义上传文件的行为，比如：
         * 临时目录位置
         * 上传大小限制
         * 单个文件最大大小
         */
        factory.setLocation(appConfig.getProjectFolder() + Constants.FILE_FOLDER_FILE + Constants.FILE_FOLDER_TEMP);
        return factory.createMultipartConfig();
    }
}
